import { describe, expect, test } from "bun:test";
import {
	awsAmzDate,
	awsCanonicalParams,
	awsDateStamp,
	AWS_NACL_MAX_RULES,
	awsSigningKey,
	awsUriEncode,
	buildAwsEc2Request,
	computeAwsNaclRuleDiff,
	isAwsNaclManagedRule,
	normalizeAwsIpv4Cidr,
	normalizeAwsRegion,
	normalizeAwsRuleNumberStart,
	parseAwsErrorXml,
	parseAwsNaclEntriesXml,
	parseAwsNaclListXml,
	parseAwsNaclProviderConfig,
	type AwsNaclExistingEntry,
} from "../src/services/firewall-sync/aws-nacl-adapter.ts";
import { toHex } from "../src/utils/crypto.ts";

function managedEntry(ruleNumber: number, cidrBlock: string): AwsNaclExistingEntry {
	return { ruleNumber, ruleAction: "deny", protocol: "-1", cidrBlock, portRangeFrom: null, portRangeTo: null };
}

function allowEntry(ruleNumber: number, portFrom: number): AwsNaclExistingEntry {
	return { ruleNumber, ruleAction: "allow", protocol: "6", cidrBlock: "0.0.0.0/0", portRangeFrom: portFrom, portRangeTo: portFrom };
}

const DESCRIBE_NETWORK_ACLS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeNetworkAclsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <networkAclSet>
    <item>
      <networkAclId>acl-5fb85d36</networkAclId>
      <vpcId>vpc-11ad4878</vpcId>
      <default>false</default>
      <entrySet>
        <item>
          <ruleNumber>1</ruleNumber>
          <protocol>-1</protocol>
          <ruleAction>deny</ruleAction>
          <egress>false</egress>
          <cidrBlock>203.0.113.1/32</cidrBlock>
        </item>
        <item>
          <ruleNumber>100</ruleNumber>
          <protocol>6</protocol>
          <ruleAction>allow</ruleAction>
          <egress>false</egress>
          <cidrBlock>0.0.0.0/0</cidrBlock>
          <portRange>
            <from>22</from>
            <to>22</to>
          </portRange>
        </item>
        <item>
          <ruleNumber>100</ruleNumber>
          <protocol>6</protocol>
          <ruleAction>allow</ruleAction>
          <egress>true</egress>
          <cidrBlock>0.0.0.0/0</cidrBlock>
        </item>
        <item>
          <ruleNumber>32767</ruleNumber>
          <protocol>-1</protocol>
          <ruleAction>deny</ruleAction>
          <egress>false</egress>
          <cidrBlock>0.0.0.0/0</cidrBlock>
        </item>
      </entrySet>
      <associationSet>
        <item>
          <networkAclAssociationId>aclassoc-5c6f9b34</networkAclAssociationId>
          <networkAclId>acl-5fb85d36</networkAclId>
          <subnetId>subnet-ff669596</subnetId>
        </item>
      </associationSet>
      <tagSet/>
    </item>
  </networkAclSet>
</DescribeNetworkAclsResponse>`;

const DESCRIBE_NETWORK_ACLS_LIST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeNetworkAclsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <networkAclSet>
    <item>
      <networkAclId>acl-5fb85d36</networkAclId>
      <vpcId>vpc-11ad4878</vpcId>
      <default>false</default>
      <entrySet>
        <item><ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
      </entrySet>
      <associationSet/>
      <tagSet/>
    </item>
    <item>
      <networkAclId>acl-2cb85d45</networkAclId>
      <vpcId>vpc-11ad4878</vpcId>
      <default>true</default>
      <entrySet>
        <item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
      </entrySet>
      <associationSet/>
      <tagSet/>
    </item>
  </networkAclSet>
</DescribeNetworkAclsResponse>`;

const ERROR_XML = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Errors>
    <Error>
      <Code>AuthFailure</Code>
      <Message>AWS was not able to validate the provided access credentials</Message>
    </Error>
  </Errors>
  <RequestID>b5f6b3b5-e1a0-4f0e-9e3a-example</RequestID>
</Response>`;

describe("normalizeAwsRegion / parseAwsNaclProviderConfig", () => {
	test("defaults the region to us-east-1", () => {
		expect(normalizeAwsRegion(undefined)).toBe("us-east-1");
		expect(normalizeAwsRegion("")).toBe("us-east-1");
		expect(normalizeAwsRegion(" eu-west-1 ")).toBe("eu-west-1");
	});

	test("parses a full config and defaults empty fields", () => {
		const cfg = parseAwsNaclProviderConfig({ accessKeyId: " AKIA ", networkAclId: " acl-123 " });
		expect(cfg.region).toBe("us-east-1");
		expect(cfg.accessKeyId).toBe("AKIA");
		expect(cfg.networkAclId).toBe("acl-123");
		expect(cfg.secretAccessKeyEncrypted).toBe("");
		expect(cfg.sessionTokenEncrypted).toBe("");
		expect(cfg.ruleNumberStart).toBe(1);
	});
});

describe("normalizeAwsRuleNumberStart", () => {
	test("defaults to 1 for missing or invalid values", () => {
		expect(normalizeAwsRuleNumberStart(undefined)).toBe(1);
		expect(normalizeAwsRuleNumberStart(0)).toBe(1);
		expect(normalizeAwsRuleNumberStart(-5)).toBe(1);
		expect(normalizeAwsRuleNumberStart("not a number")).toBe(1);
	});

	test("passes through a valid start", () => {
		expect(normalizeAwsRuleNumberStart(500)).toBe(500);
	});

	test("caps the start so the reserved 20-slot block never exceeds the valid 1-32766 rule number range", () => {
		expect(normalizeAwsRuleNumberStart(32_766)).toBe(32_747);
	});
});

describe("normalizeAwsIpv4Cidr", () => {
	test("appends /32 to a bare address - AWS rejects a bare address for the cidrBlock parameter", () => {
		expect(normalizeAwsIpv4Cidr("15.169.249.14")).toBe("15.169.249.14/32");
	});

	test("leaves an already-prefixed CIDR untouched", () => {
		expect(normalizeAwsIpv4Cidr("203.0.113.0/24")).toBe("203.0.113.0/24");
		expect(normalizeAwsIpv4Cidr("15.169.249.14/32")).toBe("15.169.249.14/32");
	});
});

describe("awsUriEncode / awsCanonicalParams", () => {
	test("escapes reserved characters encodeURIComponent leaves untouched, per SigV4's RFC 3986 requirement", () => {
		expect(awsUriEncode("a b")).toBe("a%20b");
		expect(awsUriEncode("a!b'c(d)e*f")).toBe("a%21b%27c%28d%29e%2Af");
	});

	test("sorts parameters by key and encodes both key and value", () => {
		expect(awsCanonicalParams({ Version: "2016-11-15", Action: "DescribeNetworkAcls" })).toBe("Action=DescribeNetworkAcls&Version=2016-11-15");
	});
});

describe("awsAmzDate / awsDateStamp", () => {
	test("formats a fixed date as AWS's compact ISO8601 basic format", () => {
		const date = new Date("2015-08-30T12:36:00.000Z");
		expect(awsAmzDate(date)).toBe("20150830T123600Z");
		expect(awsDateStamp(date)).toBe("20150830");
	});
});

describe("awsSigningKey", () => {
	test("derives a 32-byte (SHA-256-sized) key deterministically", async () => {
		const key = await awsSigningKey("secret", "20150830", "us-east-1", "ec2");
		expect(key.length).toBe(32);
		expect(toHex(await awsSigningKey("secret", "20150830", "us-east-1", "ec2"))).toBe(toHex(key));
	});

	test("changes when the secret, date, region, or service changes - each is a link in the HMAC chain", async () => {
		const base = toHex(await awsSigningKey("secret", "20150830", "us-east-1", "ec2"));
		expect(toHex(await awsSigningKey("other-secret", "20150830", "us-east-1", "ec2"))).not.toBe(base);
		expect(toHex(await awsSigningKey("secret", "20150831", "us-east-1", "ec2"))).not.toBe(base);
		expect(toHex(await awsSigningKey("secret", "20150830", "eu-west-1", "ec2"))).not.toBe(base);
		expect(toHex(await awsSigningKey("secret", "20150830", "us-east-1", "s3"))).not.toBe(base);
	});
});

describe("buildAwsEc2Request", () => {
	test("builds the POST request with signed headers and a form-encoded body", async () => {
		const date = new Date("2015-08-30T12:36:00.000Z");
		const spec = await buildAwsEc2Request(
			{ region: "us-east-1", accessKeyId: "AKIDEXAMPLE" },
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"",
			"DescribeNetworkAcls",
			{ "NetworkAclId.1": "acl-5fb85d36" },
			date,
		);
		expect(spec.url).toBe("https://ec2.us-east-1.amazonaws.com/");
		const headers = spec.init.headers as Record<string, string>;
		expect(headers.host).toBe("ec2.us-east-1.amazonaws.com");
		expect(headers["x-amz-date"]).toBe("20150830T123600Z");
		expect(headers.authorization).toContain("Credential=AKIDEXAMPLE/20150830/us-east-1/ec2/aws4_request");
		expect(headers.authorization).toContain("SignedHeaders=content-type;host;x-amz-date");
		expect(spec.init.body).toBe("Action=DescribeNetworkAcls&NetworkAclId.1=acl-5fb85d36&Version=2016-11-15");
	});

	test("includes the session token header and adds it to SignedHeaders when set", async () => {
		const date = new Date("2015-08-30T12:36:00.000Z");
		const spec = await buildAwsEc2Request({ region: "us-east-1", accessKeyId: "AKIDEXAMPLE" }, "secret", "a-session-token", "DescribeNetworkAcls", {}, date);
		const headers = spec.init.headers as Record<string, string>;
		expect(headers["x-amz-security-token"]).toBe("a-session-token");
		expect(headers.authorization).toContain("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token");
	});

	test("changes the signature when the region or the params change", async () => {
		const date = new Date("2015-08-30T12:36:00.000Z");
		const base = await buildAwsEc2Request({ region: "us-east-1", accessKeyId: "AK" }, "S", "", "DescribeNetworkAcls", {}, date);
		const otherRegion = await buildAwsEc2Request({ region: "eu-west-1", accessKeyId: "AK" }, "S", "", "DescribeNetworkAcls", {}, date);
		const otherParams = await buildAwsEc2Request({ region: "us-east-1", accessKeyId: "AK" }, "S", "", "CreateNetworkAclEntry", {}, date);
		const baseAuth = (base.init.headers as Record<string, string>).authorization;
		expect((otherRegion.init.headers as Record<string, string>).authorization).not.toBe(baseAuth);
		expect((otherParams.init.headers as Record<string, string>).authorization).not.toBe(baseAuth);
	});
});

describe("parseAwsErrorXml", () => {
	test("extracts the code and message from an AWS error response", () => {
		expect(parseAwsErrorXml(ERROR_XML)).toEqual({ code: "AuthFailure", message: "AWS was not able to validate the provided access credentials" });
	});

	test("returns null when there's no <Error> block", () => {
		expect(parseAwsErrorXml(DESCRIBE_NETWORK_ACLS_XML)).toBeNull();
	});
});

describe("parseAwsNaclEntriesXml", () => {
	test("parses ingress entries only, correctly bounding the outer <item> despite nested entrySet <item> tags", () => {
		const entries = parseAwsNaclEntriesXml(DESCRIBE_NETWORK_ACLS_XML);
		// 4 ingress entries in the fixture; the egress=true duplicate at rule 100 must be excluded.
		expect(entries).toHaveLength(3);
		expect(entries).toContainEqual({ ruleNumber: 1, ruleAction: "deny", protocol: "-1", cidrBlock: "203.0.113.1/32", portRangeFrom: null, portRangeTo: null });
		expect(entries).toContainEqual({ ruleNumber: 100, ruleAction: "allow", protocol: "6", cidrBlock: "0.0.0.0/0", portRangeFrom: 22, portRangeTo: 22 });
		expect(entries).toContainEqual({ ruleNumber: 32_767, ruleAction: "deny", protocol: "-1", cidrBlock: "0.0.0.0/0", portRangeFrom: null, portRangeTo: null });
	});

	test("returns an empty array when there's no networkAclSet", () => {
		expect(parseAwsNaclEntriesXml("<DescribeNetworkAclsResponse></DescribeNetworkAclsResponse>")).toEqual([]);
	});
});

describe("parseAwsNaclListXml", () => {
	test("parses every top-level Network ACL despite each one nesting its own entrySet <item> tags", () => {
		const items = parseAwsNaclListXml(DESCRIBE_NETWORK_ACLS_LIST_XML);
		expect(items).toEqual([
			{ networkAclId: "acl-5fb85d36", vpcId: "vpc-11ad4878", isDefault: false },
			{ networkAclId: "acl-2cb85d45", vpcId: "vpc-11ad4878", isDefault: true },
		]);
	});
});

describe("isAwsNaclManagedRule", () => {
	test("only a plain ingress deny-all-protocols rule with no port restriction is BurrowGate's own", () => {
		expect(isAwsNaclManagedRule(managedEntry(1, "203.0.113.1/32"))).toBe(true);
		expect(isAwsNaclManagedRule(allowEntry(100, 22))).toBe(false);
		expect(isAwsNaclManagedRule({ ruleNumber: 5, ruleAction: "deny", protocol: "6", cidrBlock: "203.0.113.1/32", portRangeFrom: 25, portRangeTo: 25 })).toBe(
			false,
		);
	});
});

describe("computeAwsNaclRuleDiff", () => {
	test("creates rules at the reserved rule numbers when the ACL has nothing in that range yet", () => {
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32", "203.0.113.2/32"], [], 1);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([
			{ ruleNumber: 1, cidrBlock: "203.0.113.1/32" },
			{ ruleNumber: 2, cidrBlock: "203.0.113.2/32" },
		]);
	});

	test("keeps rules whose CIDR is still desired, deletes the rest, and reuses freed rule numbers", () => {
		const existing = [managedEntry(1, "203.0.113.1/32"), managedEntry(2, "203.0.113.99/32"), managedEntry(6, "203.0.113.2/32")];
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"], existing, 1);
		expect(diff.toDelete).toEqual([2]);
		expect(diff.toCreate).toEqual([{ ruleNumber: 2, cidrBlock: "203.0.113.3/32" }]);
	});

	test("produces no changes when the existing set already matches the desired set exactly", () => {
		const existing = [managedEntry(1, "203.0.113.1/32"), managedEntry(2, "203.0.113.2/32")];
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32", "203.0.113.2/32"], existing, 1);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([]);
	});

	test("hard-caps at the 20-slot limit even if the caller passes a larger desired list", () => {
		const desired = Array.from({ length: 30 }, (_, i) => `203.0.113.${i}/32`);
		const diff = computeAwsNaclRuleDiff(desired, [], 1);
		expect(diff.toCreate.length).toBe(AWS_NACL_MAX_RULES);
		expect(diff.toCreate.every((entry) => entry.ruleNumber >= 1 && entry.ruleNumber <= 20)).toBe(true);
	});

	test("never deletes or reuses the rule number of a rule the admin set up manually - this is what stops a lockout", () => {
		const existing = [allowEntry(1, 22), allowEntry(2, 443), managedEntry(3, "203.0.113.1/32")];
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32", "203.0.113.2/32"], existing, 1);
		expect(diff.toDelete).not.toContain(1);
		expect(diff.toDelete).not.toContain(2);
		expect(diff.toCreate).toEqual([{ ruleNumber: 4, cidrBlock: "203.0.113.2/32" }]);
	});

	test("ignores rules outside the reserved rule-number range entirely - they never count against capacity", () => {
		const existing = [managedEntry(1, "203.0.113.1/32"), allowEntry(100, 22), managedEntry(32_767, "0.0.0.0/0")];
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32", "203.0.113.2/32"], existing, 1);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([{ ruleNumber: 2, cidrBlock: "203.0.113.2/32" }]);
	});

	test("respects a custom rule number start", () => {
		const diff = computeAwsNaclRuleDiff(["203.0.113.1/32"], [], 500);
		expect(diff.toCreate).toEqual([{ ruleNumber: 500, cidrBlock: "203.0.113.1/32" }]);
	});

	test("reduces effective capacity by however many slots foreign rules occupy in the reserved range", () => {
		const foreign = Array.from({ length: 5 }, (_, i) => allowEntry(1 + i, 1000 + i));
		const desired = Array.from({ length: 30 }, (_, i) => `203.0.113.${i}/32`);
		const diff = computeAwsNaclRuleDiff(desired, foreign, 1);
		expect(diff.toCreate.length).toBe(AWS_NACL_MAX_RULES - 5);
		expect(diff.toCreate.every((entry) => entry.ruleNumber >= 6)).toBe(true);
	});
});
