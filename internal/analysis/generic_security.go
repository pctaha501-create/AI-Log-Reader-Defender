package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

// analyzeGenericSecurity applies vendor-neutral detections to normalized fields
// and retained raw fields. These rules deliberately describe indicators, not
// confirmed compromise; each finding keeps the source event index and evidence.
func analyzeGenericSecurity(events []model.Event) []model.Finding {
	findings := make([]model.Finding, 0)
	for i, event := range events {
		text := genericEventText(event)
		switch {
		case containsAny(text,
			"vssadmin delete shadows",
			"delete shadows /all",
			"wbadmin delete catalog",
			"backup catalog deleted",
			"backup repository deleted",
			"backup retention disabled",
			"immutable backup disabled",
			"remove all backups",
			"delete all backups",
		):
			findings = append(findings, finding(
				"generic.backup-destruction-indicator", "critical",
				"Backup or recovery data destruction indicator",
				"The event contains a command or state change associated with deleting backup catalogs, shadow copies, repositories, or immutability controls. Verify the actor, target, authorization, and recovery-point availability.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if containsAny(text,
			"mfa disabled",
			"multi-factor authentication disabled",
			"multifactor authentication disabled",
			"two-factor authentication disabled",
			"2fa disabled",
			"conditional access disabled",
			"security defaults disabled",
		) {
			findings = append(findings, finding(
				"generic.identity-strong-auth-disabled", "high",
				"Strong authentication or access policy disabled",
				"The event indicates that MFA, two-factor authentication, conditional access, or a comparable identity safeguard was disabled. Confirm the affected identity scope, initiator, policy, and approved change.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if hasPublicExposureIndicator(text) {
			findings = append(findings, finding(
				"generic.cloud-public-exposure", "high",
				"Cloud or network resource made publicly reachable",
				"The event combines a public-access indicator with a storage, database, ingress, security-group, or firewall resource. Verify the resource, source range, effective policy, and whether public exposure was intended.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if hasPrivilegedContainerIndicator(text) {
			findings = append(findings, finding(
				"generic.container-privileged-execution", "high",
				"Privileged container or host mount configuration",
				"The event indicates privileged container execution or a sensitive host mount. Review the workload owner, image, runtime, namespace, mounted paths, and deployment approval.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if hasIndustrialSafetyOverride(text) {
			findings = append(findings, finding(
				"generic.industrial-safety-override", "critical",
				"Industrial safety interlock or emergency stop override",
				"The event contains an industrial safety interlock or emergency-stop bypass, disablement, or override indicator. Treat this as an urgent operational safety signal and follow the site's incident and process-safety procedures.",
				[]int{i}, []string{eventEvidence(event)},
			))
		} else if hasIndustrialProgramChange(text) {
			findings = append(findings, finding(
				"generic.industrial-control-program-change", "high",
				"Industrial control program changed or downloaded",
				"The event indicates a PLC, SCADA, or control-logic program change or download. Verify the engineering workstation, operator, controller, program revision, and maintenance authorization.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if hasWebInjectionIndicator(text) {
			findings = append(findings, finding(
				"generic.web-injection-attempt", "medium",
				"Web request contains an injection indicator",
				"The event contains a recognizable SQL injection or path-traversal pattern. This indicates a suspicious request, not proof that the application was exploited; correlate the request, response status, WAF action, and application logs.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if containsAny(text,
			"audit logging disabled",
			"security audit disabled",
			"auditd stopped",
			"audit service stopped",
			"security logging disabled",
		) {
			findings = append(findings, finding(
				"generic.audit-collection-disabled", "high",
				"Security audit or logging collection disabled",
				"The event indicates that security audit collection or a logging service was disabled or stopped. Determine whether events were lost, identify the actor, and restore required collection through approved procedures.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}

		if hasPersistenceCreationIndicator(text) {
			findings = append(findings, finding(
				"generic.persistence-mechanism-created", "medium",
				"New scheduled task or service persistence indicator",
				"The event indicates creation or installation of a scheduled task or service. Review its command, executable path, account, trigger, signer, and change authorization.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}
	}
	return findings
}

func genericEventText(event model.Event) string {
	parts := []string{
		event.Source, event.Host, event.Provider, event.EventID, event.Level, event.Message,
	}
	keys := make([]string, 0, len(event.Raw))
	for key := range event.Raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if value := event.Raw[key]; value != nil {
			parts = append(parts, key+"="+fmt.Sprint(value))
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func hasPublicExposureIndicator(text string) bool {
	public := containsAny(text, "0.0.0.0/0", "::/0", "publicly accessible", "public access enabled", "allow public access", "internet accessible")
	resource := containsAny(text, "bucket", "blob storage", "object storage", "storage account", "database", "security group", "ingress rule", "firewall rule", "network acl")
	return public && resource
}

func hasPrivilegedContainerIndicator(text string) bool {
	privileged := containsAny(text, "privileged=true", "privileged: true", "privileged container", "allowprivilegeescalation=true")
	container := containsAny(text, "container", "kubernetes", "kubelet", "docker", "podman", "cri-o")
	hostMount := containsAny(text, "/var/run/docker.sock", "hostpath", "host path mount", "mount path=/host", "mount=/host")
	return privileged && container || hostMount && container
}

func hasIndustrialSafetyOverride(text string) bool {
	safetyControl := containsAny(text, "interlock", "emergency stop", "e-stop", "safety relay", "safety function")
	override := containsAny(text, "bypass", "bypassed", "disabled", "disable", "override", "overridden", "defeated")
	return safetyControl && override
}

func hasIndustrialProgramChange(text string) bool {
	controller := containsAny(text, "plc", "scada", "industrial controller", "programmable logic controller", "dcs")
	change := containsAny(text, "program downloaded", "logic downloaded", "ladder logic modified", "control program changed", "controller program updated")
	return controller && change
}

func hasWebInjectionIndicator(text string) bool {
	sqlInjection := containsAny(text, "union select", " or 1=1", "' or '1'='1", "\" or \"1\"=\"1", "information_schema", "sleep(", "benchmark(")
	pathTraversal := containsAny(text, "../", "..%2f", "%2e%2e%2f", "%2e%2e/", "..\\")
	return sqlInjection || pathTraversal
}

func hasPersistenceCreationIndicator(text string) bool {
	created := containsAny(text, "created scheduled task", "scheduled task created", "new scheduled task", "service installed", "new service installed", "systemd unit created", "service was created")
	mechanism := containsAny(text, "scheduled task", "systemd", "service", "launch daemon", "startup entry")
	return created && mechanism
}
