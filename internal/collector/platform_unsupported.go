//go:build !windows && !linux
package collector
import("fmt";"io";"time")
func Platform()string{return "unsupported"}
func Collect(_ io.Writer,_ time.Duration)(int,error){return 0,fmt.Errorf("native collection is supported only on Windows and Linux")}
