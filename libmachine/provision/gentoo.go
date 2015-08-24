package provision

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/docker/machine/drivers"
	"github.com/docker/machine/libmachine/auth"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/provision/pkgaction"
	"github.com/docker/machine/libmachine/swarm"
	"github.com/docker/machine/log"
	"github.com/docker/machine/utils"
)

func init() {
	Register("Gentoo", &RegisteredProvisioner{
		New: NewGentooProvisioner,
	})
}

func NewGentooProvisioner(d drivers.Driver) Provisioner {
	return &GentooProvisioner{
		AlreadySynced: false,
		GenericProvisioner: GenericProvisioner {
			DockerOptionsDir:  "/etc/docker",
			//DaemonOptionsFile: "",
			OsReleaseId:       "gentoo",
			Packages: []string{
				"curl",
				"docker",
			},
			Driver: d,
		},
	}
}

type GentooProvisioner struct {
	AlreadySynced        bool
	GenericProvisioner
}

func (provisioner *GentooProvisioner) Service(name string, action pkgaction.ServiceAction) error {
	// daemon-reload to catch config updates
	if _, err := provisioner.SSHCommand("sudo systemctl daemon-reload"); err != nil {
		return err
	}

	command := fmt.Sprintf("sudo systemctl %s %s", action.String(), name)

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *GentooProvisioner) Package(name string, action pkgaction.PackageAction) error {
	var command, emergeAction string
	var sync bool

	if action == pkgaction.Remove || action == pkgaction.Install {
		command = fmt.Sprintf("portageq has_version / %s", name)
		if _, err := provisioner.SSHCommand(command); err == nil {
			if action == pkgaction.Remove {
				return nil
			}
		} else if action == pkgaction.Install {
			return nil
		}
	}

	sync = false
	if !provisioner.AlreadySynced {
		if action == pkgaction.Upgrade {
			sync = true
		} else if action == pkgaction.Install {
			if _, err := provisioner.SSHCommand("[ -e \"$(portageq get_repo_path / gentoo)\" ]"); err != nil {
				sync = true
			}
		}
	}

	if sync {
		if _, err := provisioner.SSHCommand("sudo emerge --sync"); err != nil {
			return err
		}
		provisioner.AlreadySynced = true
	}

	emergeAction = ""

	switch action {
	case pkgaction.Upgrade:
		emergeAction = "--update"
	case pkgaction.Remove:
		emergeAction = "--unmerge"
	}

	command = fmt.Sprintf("sudo emerge %s %s", emergeAction, name)

	log.Debugf("package: action=%s name=%s", action.String(), name)

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *GentooProvisioner) dockerDaemonResponding() bool {
	if _, err := provisioner.SSHCommand("sudo docker version"); err != nil {
		log.Warnf("Error getting SSH command to check if the daemon is up: %s", err)
		return false
	}

	// The daemon is up if the command worked.  Carry on.
	return true
}

func (provisioner *GentooProvisioner) Provision(swarmOptions swarm.SwarmOptions, authOptions auth.AuthOptions, engineOptions engine.EngineOptions) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions

	if provisioner.EngineOptions.StorageDriver == "" {
		provisioner.EngineOptions.StorageDriver = "aufs"
	}

	// HACK: since gentoo does not come with sudo by default we install
	log.Debug("installing sudo")
	if _, err := provisioner.SSHCommand("if ! type sudo; then emerge sudo; fi"); err != nil {
		return err
	}

	log.Debug("setting hostname")
	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	log.Debug("installing base packages")
	for _, pkg := range provisioner.Packages {
		if err := provisioner.Package(pkg, pkgaction.Install); err != nil {
			return err
		}
	}

	if err := provisioner.Service("docker", pkgaction.Enable); err != nil {
		return err
	}

	if err := provisioner.Service("docker", pkgaction.Restart); err != nil {
		return err
	}

	log.Debug("waiting for docker daemon")
	if err := utils.WaitFor(provisioner.dockerDaemonResponding); err != nil {
		return err
	}

	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	log.Debug("configuring auth")
	if err := ConfigureAuth(provisioner); err != nil {
		return err
	}

	log.Debug("configuring swarm")
	if err := configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions); err != nil {
		return err
	}

	// enable in systemd
	log.Debug("enabling docker in systemd")
	if err := provisioner.Service("docker", pkgaction.Enable); err != nil {
		return err
	}

	return nil
}

func (provisioner *GentooProvisioner) GenerateDockerOptions(dockerPort int) (*DockerOptions, error) {
	var (
		engineCfg bytes.Buffer
	)

	log.Debug("checking init system")
	_, err := provisioner.SSHCommand("[ systemd = $(basename $(readlink /proc/1/exe)) ]")
	systemd := err == nil

	driverNameLabel := fmt.Sprintf("provider=%s", provisioner.Driver.DriverName())
	provisioner.EngineOptions.Labels = append(provisioner.EngineOptions.Labels, driverNameLabel)

	var engineConfigTmpl string

	if systemd {
		provisioner.DaemonOptionsFile = "/etc/systemd/system/docker.service"
		engineConfigTmpl = `[Service]
ExecStart=/usr/bin/docker -d -H tcp://0.0.0.0:{{.DockerPort}} -H unix:///var/run/docker.sock --storage-driver {{.EngineOptions.StorageDriver}} --tlsverify --tlscacert {{.AuthOptions.CaCertRemotePath}} --tlscert {{.AuthOptions.ServerCertRemotePath}} --tlskey {{.AuthOptions.ServerKeyRemotePath}} {{ range .EngineOptions.Labels }}--label {{.}} {{ end }}{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}} {{ end }}{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}} {{ end }}{{ range .EngineOptions.ArbitraryFlags }}--{{.}} {{ end }}
MountFlags=slave
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
Environment={{range .EngineOptions.Env}}{{ printf "%q" . }} {{end}}

[Install]
WantedBy=multi-user.target
`
	} else {
		// OpenRC
		provisioner.DaemonOptionsFile = "/etc/conf.d/docker"
		engineConfigTmpl = `
DOCKER_OPTS='
-H tcp://0.0.0.0:{{.DockerPort}}
-H unix:///var/run/docker.sock
--storage-driver {{.EngineOptions.StorageDriver}}
--tlsverify
--tlscacert {{.AuthOptions.CaCertRemotePath}}
--tlscert {{.AuthOptions.ServerCertRemotePath}}
--tlskey {{.AuthOptions.ServerKeyRemotePath}}
{{ range .EngineOptions.Labels }}--label {{.}}
{{ end }}{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}}
{{ end }}{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}}
{{ end }}{{ range .EngineOptions.ArbitraryFlags }}--{{.}}
{{ end }}
'
{{range .EngineOptions.Env}}export \"{{ printf "%q" . }}\"
{{end}}
`
	}

	t, err := template.New("engineConfig").Parse(engineConfigTmpl)
	if err != nil {
		return nil, err
	}

	engineConfigContext := EngineConfigContext{
		DockerPort:    dockerPort,
		AuthOptions:   provisioner.AuthOptions,
		EngineOptions: provisioner.EngineOptions,
	}

	t.Execute(&engineCfg, engineConfigContext)

	return &DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: provisioner.DaemonOptionsFile,
	}, nil
}
