package ingest
import("strings";"testing";"time")
func TestJSONLBOMAndBlankLines(t *testing.T){e,err:=ReadJSONL(strings.NewReader("\uFEFF\n{\"timestamp\":\"2026-01-01T00:00:00Z\",\"message\":\"ok\",\"custom\":\"kept\"}\n"));if err!=nil{t.Fatal(err)};if len(e)!=1||e[0].Message!="ok"||e[0].Raw["custom"]!="kept"{t.Fatalf("unexpected events: %#v",e)}}
func TestJSONLReportsLineNumber(t *testing.T){_,err:=ReadJSONL(strings.NewReader("{}\nnot-json\n"));if err==nil||!strings.Contains(err.Error(),"line 2"){t.Fatalf("expected line 2 error, got %v",err)}}
func TestJSONLRejectsNonObjectRecords(t *testing.T){for _,s:=range []string{"[]\n","null\n","42\n"}{if _,err:=ReadJSONL(strings.NewReader(s));err==nil{t.Errorf("expected error for %q",s)}}}
func TestJournaldMicroseconds(t *testing.T){e,err:=ReadJSONL(strings.NewReader("{\"__REALTIME_TIMESTAMP\":1767225600000000,\"MESSAGE\":\"journal\"}\n"));if err!=nil{t.Fatal(err)};want:=time.Date(2026,1,1,0,0,0,0,time.UTC);if !e[0].Timestamp.Equal(want){t.Fatalf("got %s want %s",e[0].Timestamp,want)}}
