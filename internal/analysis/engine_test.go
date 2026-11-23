package analysis

import (
 "testing"
 "time"
 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)
func hasRule(r model.Report,id string)bool{for _,f:=range r.Findings{if f.RuleID==id{return true}};return false}
func TestRepeatedFailuresDetection(t *testing.T){base:=time.Date(2026,1,1,0,0,0,0,time.UTC);e:=make([]model.Event,5);for i:=range e{e[i]=model.Event{EventID:"4625",SourceIP:"198.51.100.20",Message:"An account failed to log on",Timestamp:base.Add(time.Duration(i)*time.Minute)}};if !hasRule(Analyze(e),"authentication.repeated-failures"){t.Fatal("expected repeated failures finding")}}
func TestRepeatedFailuresRespectWindow(t *testing.T){base:=time.Date(2026,1,1,0,0,0,0,time.UTC);e:=make([]model.Event,6);for i:=range e{e[i]=model.Event{EventID:"4625",SourceIP:"198.51.100.20",Timestamp:base.Add(time.Duration(i)*15*time.Minute)}};if hasRule(Analyze(e),"authentication.repeated-failures"){t.Fatal("spread-out failures must not trigger the 10-minute rule")}}
func TestRepeatedFailuresIgnoreUnknownTimestamps(t *testing.T){e:=make([]model.Event,5);for i:=range e{e[i]=model.Event{EventID:"4625",SourceIP:"198.51.100.20",Message:"An account failed to log on"}};if hasRule(Analyze(e),"authentication.repeated-failures"){t.Fatal("events without timestamps must not be claimed to fall within a time window")}}
func TestRepeatedFailuresWithinWindow(t *testing.T){base:=time.Date(2026,1,1,0,0,0,0,time.UTC);e:=make([]model.Event,5);for i:=range e{e[i]=model.Event{EventID:"4776",User:"alice",Timestamp:base.Add(time.Duration(i)*time.Minute)}};if !hasRule(Analyze(e),"authentication.repeated-failures"){t.Fatal("expected five failures within the window")}}
func TestAccountCreationPrivilegeCorrelation(t *testing.T){e:=[]model.Event{{EventID:"4720",Host:"pc-1",User:"alice",Message:"A user account was created"},{EventID:"4732",Host:"pc-1",User:"alice",Message:"Member added to the Administrators group"}};if !hasRule(Analyze(e),"correlation.account-created-then-privileged"){t.Fatal("expected same-account correlation finding")}}
func TestAccountCreationPrivilegeCorrelationRejectsDifferentUsers(t *testing.T){e:=[]model.Event{{EventID:"4720",Host:"pc-1",User:"alice",Message:"A user account was created"},{EventID:"4732",Host:"pc-1",User:"bob",Message:"Member added to the Administrators group"}};if hasRule(Analyze(e),"correlation.account-created-then-privileged"){t.Fatal("different accounts on the same host must not correlate")}}
func TestAccountCreationPrivilegeCorrelationRejectsDifferentHosts(t *testing.T){e:=[]model.Event{{EventID:"4720",Host:"pc-1",User:"alice"},{EventID:"4732",Host:"pc-2",User:"alice"}};if hasRule(Analyze(e),"correlation.account-created-then-privileged"){t.Fatal("same account name on different hosts must not correlate")}}
func TestSecurityRules(t *testing.T){e:=[]model.Event{{EventID:"1102"},{EventID:"4720"},{EventID:"4728"},{EventID:"4726"},{Message:"Ransomware detected"}};r:=Analyze(e);for _,id:=range []string{"audit.log-cleared","identity.account-created","identity.privilege-change","identity.account-or-membership-removed","endpoint.malware-indicator"}{if !hasRule(r,id){t.Errorf("expected rule %s",id)}}}
func TestFindingIDsAreStable(t *testing.T){e:=[]model.Event{{EventID:"1102"}};if Analyze(e).Findings[0].ID!=Analyze(e).Findings[0].ID{t.Fatal("finding IDs should be stable")}}
func TestPublicIP(t *testing.T){if !IsPublicIP("8.8.8.8")||IsPublicIP("192.168.1.1")||IsPublicIP("127.0.0.1")||IsPublicIP("169.254.1.1"){t.Fatal("public IP classification failed")}}
