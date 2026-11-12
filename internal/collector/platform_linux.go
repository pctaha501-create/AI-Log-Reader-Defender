//go:build linux
package collector
import("bufio";"bytes";"encoding/json";"fmt";"io";"os/exec";"time")
func Platform()string{return "linux"}
func Collect(w io.Writer,since time.Duration)(int,error){cmd:=exec.Command("journalctl","--since",sinceArg(since),"--output=json","--no-pager");out,err:=cmd.Output();if err!=nil{return 0,fmt.Errorf("read system journal with journalctl (current user may need journal access): %w",err)};s:=bufio.NewScanner(bytes.NewReader(out));s.Buffer(make([]byte,64*1024),8*1024*1024);records:=[]Record{};for s.Scan(){m:=map[string]any{};if err:=json.Unmarshal(s.Bytes(),&m);err!=nil{return 0,fmt.Errorf("parse journal JSON record: %w",err)};records=append(records,Record{"timestamp":m["__REALTIME_TIMESTAMP"],"source":"journald","host":m["_HOSTNAME"],"provider":m["SYSLOG_IDENTIFIER"],"message":m["MESSAGE"],"level":m["PRIORITY"],"user":m["_UID"],"raw_journal":m})};if err:=s.Err();err!=nil{return 0,err};return writeRecords(w,records)}
