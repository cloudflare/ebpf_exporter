package kernel_version

import (
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/go-version"
	"golang.org/x/sys/unix"
)

func GetAndParseKernelVersion(kernelVersionRegex *regexp.Regexp) (*version.Version, error) {
	var uname unix.Utsname
	err := unix.Uname(&uname)
	if err != nil {
		log.Fatal(err)
	}

	kernelVersionRaw := kernelVersionRegex.FindString(string(uname.Release[:]))
	if len(kernelVersionRaw) == 0 {
		return nil, fmt.Errorf("failed to parse kernel release: %q", kernelVersionRaw)
	}

	kernelVersion, err := version.NewVersion(kernelVersionRaw)
	if err != nil {
		return nil, err
	}

	return kernelVersion, nil
}

func ParseKernelVersionConstraint(kernelVersionConstraintRaw string) (version.Constraints, error) {
	return version.NewConstraint(kernelVersionConstraintRaw)
}

func ApplyKernelVersionConstraint(kernelVersion *version.Version, constraints version.Constraints) bool {
	return constraints.Check(kernelVersion)
}
