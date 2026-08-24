//go:build !windows

package bundle

func copyTreeSecurityMetadata(_, _ string) error {
	return nil
}
