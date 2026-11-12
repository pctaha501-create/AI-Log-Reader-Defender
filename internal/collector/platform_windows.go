//go:build windows

package collector

import (
 "bytes"
 "encoding/xml"
 "fmt"
 "io"
 "os/exec"
 "strings"
 "time"
)

func Platform()string{return "windows"}
func Collect(w io.Writer,since time.Duration)(int,error){
 cmd:=exec.Command("wevtutil.exe","qe","Security","/rd:true","/c:2000","/f:xml")
 out,err:=cmd.Output()
 if err!=nil{return 0,fmt.Errorf("read Windows Security log with wevtutil (access may require an elevated terminal): %w",err)}
 dec:=xml.NewDecoder(bytes.NewReader(out));records:=[]Record{};cutoff:=time.Now().Add(-since)
 for {
  tok,e:=dec.Token();if e==io.EOF{break};if e!=nil{return 0,fmt.Errorf("parse Windows event XML: %w",e)}
  start,ok:=tok.(xml.StartElement);if !ok||start.Name.Local!="Event"{continue}
  var event struct {
   System struct {
    Provider struct{Name string `xml:"Name,attr"`} `xml:"Provider"`
    EventID string `xml:"EventID"`
    Time struct{Created string `xml:"SystemTime,attr"`} `xml:"TimeCreated"`
    Channel string `xml:"Channel"`
    Computer string `xml:"Computer"`
   } `xml:"System"`
  }
  if e:=dec.DecodeElement(&event,&start);e!=nil{return 0,fmt.Errorf("decode Windows event: %w",e)}
  ts,_:=time.Parse(time.RFC3339Nano,event.System.Time.Created)
  if ts.IsZero()||ts.Before(cutoff){continue}
  records=append(records,Record{"timestamp":ts,"source":event.System.Channel,"host":event.System.Computer,"event_id":strings.TrimSpace(event.System.EventID),"provider":event.System.Provider.Name})
 }
 return writeRecords(w,records)
}
