//go:build !windows

package backend

import "fmt"

func platformProcessTreeRSS(int) (int64, error) {
	return 0, fmt.Errorf("process rss unsupported")
}
