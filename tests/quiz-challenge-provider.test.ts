import { describe, expect, test } from "bun:test";
import { quizProvider } from "../src/challenges/providers/quiz.ts";
import type { ChallengeVerifyContext } from "../src/challenges/types.ts";

const verifyContext: ChallengeVerifyContext = {
	flowId: "flow_1",
	siteId: "site_1",
	clientIp: "203.0.113.10",
	userAgentHash: "ua",
	expiresAt: Date.now() + 60_000,
	attempts: 0,
	createdAt: Date.now() - 60_000,
};

const createContext = { flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 };

const validConfig = {
	questions: [
		{ question: "What color is the sky?", correctAnswers: ["Blue", "blue"], wrongAnswers: ["Red", "Green", "Purple"] },
		{ question: "How many legs does a spider have?", correctAnswers: ["Eight"], wrongAnswers: ["Six", "Four", "Ten"] },
		{ question: "What is the capital of France?", correctAnswers: ["Paris"], wrongAnswers: ["London", "Berlin", "Madrid"] },
		{ question: "What do bees make?", correctAnswers: ["Honey"], wrongAnswers: ["Wax", "Silk"] },
	],
	questionCount: 3,
};

describe("quizProvider validateConfig", () => {
	test("accepts a valid config", () => {
		expect(() => quizProvider.validateConfig?.(validConfig)).not.toThrow();
	});

	test("rejects a question entry that isn't an object", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questions: ["not an object"] })).toThrow();
	});

	test("rejects a missing or oversized question", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questions: [{ correctAnswers: ["Blue"], wrongAnswers: ["Red"] }] })).toThrow();
		expect(() =>
			quizProvider.validateConfig?.({
				...validConfig,
				questions: [{ question: "a".repeat(301), correctAnswers: ["Blue"], wrongAnswers: ["Red"] }],
			}),
		).toThrow();
	});

	test("rejects missing, non-array, or empty correct answers", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questions: [{ question: "Sky color?", wrongAnswers: ["Red"] }] })).toThrow();
		expect(() =>
			quizProvider.validateConfig?.({ ...validConfig, questions: [{ question: "Sky color?", correctAnswers: [], wrongAnswers: ["Red"] }] }),
		).toThrow();
	});

	test("rejects a correct answer that's too long", () => {
		expect(() =>
			quizProvider.validateConfig?.({
				...validConfig,
				questions: [{ question: "Sky color?", correctAnswers: [`${"a".repeat(201)}`], wrongAnswers: ["Red"] }],
			}),
		).toThrow();
	});

	test("rejects a question with no wrong answers at all", () => {
		expect(() =>
			quizProvider.validateConfig?.({ ...validConfig, questions: [{ question: "Sky color?", correctAnswers: ["Blue"], wrongAnswers: [] }] }),
		).toThrow();
	});

	test("a wrong answer identical to any correct-answer variant doesn't count toward the minimum", () => {
		expect(() =>
			quizProvider.validateConfig?.({
				...validConfig,
				questions: [{ question: "Sky color?", correctAnswers: ["Blue", "blue"], wrongAnswers: ["blue"] }],
			}),
		).toThrow();
		expect(() =>
			quizProvider.validateConfig?.({
				...validConfig,
				questions: [{ question: "Sky color?", correctAnswers: ["Blue", "blue"], wrongAnswers: ["blue", "Red"] }],
			}),
		).not.toThrow();
	});

	test("rejects missing, non-array, or empty questions", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questions: [] })).toThrow();
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questions: "not an array" })).toThrow();
	});

	test("rejects an out-of-range or non-integer questionCount", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questionCount: 0 })).toThrow();
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questionCount: 21 })).toThrow();
		expect(() => quizProvider.validateConfig?.({ ...validConfig, questionCount: 1.5 })).toThrow();
	});

	test("rejects an out-of-range or non-integer passPercent", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, passPercent: 0 })).toThrow();
		expect(() => quizProvider.validateConfig?.({ ...validConfig, passPercent: 101 })).toThrow();
		expect(() => quizProvider.validateConfig?.({ ...validConfig, passPercent: 50.5 })).toThrow();
	});

	test("accepts a valid passPercent, and a missing one defaults to requiring 100%", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, passPercent: 80 })).not.toThrow();
		expect(() => quizProvider.validateConfig?.(validConfig)).not.toThrow();
	});

	test("accepts a missing questionCount (defaults client-side)", () => {
		const { questionCount, ...rest } = validConfig;
		expect(() => quizProvider.validateConfig?.(rest)).not.toThrow();
	});
});

describe("quizProvider create", () => {
	test("picks questionCount distinct questions and exposes only question text/options, keeping answers server-side", async () => {
		const material = await quizProvider.create(createContext, validConfig);
		const rounds = material.publicData.rounds as { question: string; options: string[] }[];
		expect(rounds.length).toBe(3);
		const questionsUsed = new Set(rounds.map((round) => round.question));
		expect(questionsUsed.size).toBe(3);
		for (const round of rounds) {
			expect(new Set(round.options).size).toBe(round.options.length);
		}
		expect((material.privateData.correct as string[]).length).toBe(3);
		expect(material.publicData.correct).toBeUndefined();
	});

	test("clamps questionCount down to the available question pool instead of failing", async () => {
		const material = await quizProvider.create(createContext, { ...validConfig, questionCount: 10 });
		const rounds = material.publicData.rounds as unknown[];
		expect(rounds.length).toBe(4);
	});

	test("defaults the option button colors and carries through custom ones", async () => {
		const defaults = await quizProvider.create(createContext, validConfig);
		expect(defaults.publicData.optionColor).toBe("#0f172a");
		expect(defaults.publicData.optionBorderColor).toBe("#202d4b");
		expect(defaults.publicData.optionTextColor).toBe("#e5e7eb");
		expect(defaults.publicData.accentColor).toBe("#7c3aed");

		const custom = await quizProvider.create(createContext, {
			...validConfig,
			optionColor: "#111111",
			optionBorderColor: "#222222",
			optionTextColor: "#333333",
			accentColor: "#444444",
		});
		expect(custom.publicData.optionColor).toBe("#111111");
		expect(custom.publicData.optionBorderColor).toBe("#222222");
		expect(custom.publicData.optionTextColor).toBe("#333333");
		expect(custom.publicData.accentColor).toBe("#444444");
	});

	test("validateConfig rejects a malformed hex color", () => {
		expect(() => quizProvider.validateConfig?.({ ...validConfig, accentColor: "purple" })).toThrow();
	});

	test("each round's displayed correct answer is one of that question's accepted variants", async () => {
		const material = await quizProvider.create(createContext, validConfig);
		const rounds = material.publicData.rounds as { question: string; options: string[] }[];
		const correct = material.privateData.correct as string[];
		const byQuestion = new Map(validConfig.questions.map((entry) => [entry.question, entry]));
		rounds.forEach((round, index) => {
			const entry = byQuestion.get(round.question)!;
			expect(entry.correctAnswers).toContain(correct[index]!);
			expect(round.options).toContain(correct[index]!);
			for (const option of round.options) {
				expect(option === correct[index] || entry.wrongAnswers.includes(option)).toBe(true);
			}
		});
	});

	test("picking Blue vs blue across many rounds shows the display picks vary (not always the first entry)", async () => {
		const config = {
			questions: [{ question: "Sky color?", correctAnswers: ["Blue", "blue"], wrongAnswers: ["Red"] }],
			questionCount: 1,
		};
		const seen = new Set<string>();
		for (let i = 0; i < 30; i += 1) {
			const material = await quizProvider.create(createContext, config);
			seen.add((material.privateData.correct as string[])[0]!);
		}
		expect(seen.size).toBe(2);
	});

	test("caps a question's options at 4 even when it has more than 3 wrong answers", async () => {
		const config = {
			questions: [{ question: "Pick a number", correctAnswers: ["1"], wrongAnswers: ["2", "3", "4", "5", "6"] }],
			questionCount: 1,
		};
		const material = await quizProvider.create(createContext, config);
		const rounds = material.publicData.rounds as { options: string[] }[];
		expect(rounds[0]!.options.length).toBe(4);
	});

	test("excludes a wrong answer identical to any correct-answer variant from that question's options", async () => {
		const config = {
			questions: [{ question: "Sky color?", correctAnswers: ["Blue", "blue"], wrongAnswers: ["blue", "Red"] }],
			questionCount: 1,
		};
		const material = await quizProvider.create(createContext, config);
		const rounds = material.publicData.rounds as { options: string[] }[];
		expect(rounds[0]!.options.filter((option) => option.toLowerCase() === "blue").length).toBe(1);
		expect(rounds[0]!.options).toContain("Red");
	});
});

describe("quizProvider verify", () => {
	test("accepts every answer correct, in order", async () => {
		const material = await quizProvider.create(createContext, validConfig);
		const correct = material.privateData.correct as string[];
		const result = await quizProvider.verify(verifyContext, validConfig, material.privateData, { choices: correct });
		expect(result.success).toBe(true);
	});

	test("rejects if any single answer is wrong", async () => {
		const material = await quizProvider.create(createContext, validConfig);
		const correct = material.privateData.correct as string[];
		const withOneWrong = [...correct];
		withOneWrong[0] = "definitely-not-it";
		const result = await quizProvider.verify(verifyContext, validConfig, material.privateData, { choices: withOneWrong });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("wrongAnswer");
	});

	test("rejects a missing, malformed, or wrong-length answer", async () => {
		const material = await quizProvider.create(createContext, validConfig);
		expect((await quizProvider.verify(verifyContext, validConfig, material.privateData, {})).success).toBe(false);
		expect((await quizProvider.verify(verifyContext, validConfig, material.privateData, { choices: "not-an-array" })).success).toBe(false);
		expect((await quizProvider.verify(verifyContext, validConfig, material.privateData, { choices: [] })).success).toBe(false);
		expect((await quizProvider.verify(verifyContext, validConfig, material.privateData, "not-an-object")).success).toBe(false);
	});

	describe("passPercent threshold", () => {
		const fiveQuestionConfig = {
			questions: [
				{ question: "Q1", correctAnswers: ["A1"], wrongAnswers: ["X1"] },
				{ question: "Q2", correctAnswers: ["A2"], wrongAnswers: ["X2"] },
				{ question: "Q3", correctAnswers: ["A3"], wrongAnswers: ["X3"] },
				{ question: "Q4", correctAnswers: ["A4"], wrongAnswers: ["X4"] },
				{ question: "Q5", correctAnswers: ["A5"], wrongAnswers: ["X5"] },
			],
			questionCount: 5,
			passPercent: 80,
		};

		test("passes at exactly the threshold (4 of 5 = 80%)", async () => {
			const material = await quizProvider.create(createContext, fiveQuestionConfig);
			const correct = material.privateData.correct as string[];
			const fourOfFive = [...correct];
			fourOfFive[0] = "definitely-not-it";
			const result = await quizProvider.verify(verifyContext, fiveQuestionConfig, material.privateData, { choices: fourOfFive });
			expect(result.success).toBe(true);
		});

		test("fails just under the threshold (3 of 5 = 60%)", async () => {
			const material = await quizProvider.create(createContext, fiveQuestionConfig);
			const correct = material.privateData.correct as string[];
			const threeOfFive = [...correct];
			threeOfFive[0] = "definitely-not-it";
			threeOfFive[1] = "definitely-not-it";
			const result = await quizProvider.verify(verifyContext, fiveQuestionConfig, material.privateData, { choices: threeOfFive });
			expect(result.success).toBe(false);
		});

		test("80% of 4 questions rounds up to requiring all 4 (3 of 4 = 75% still fails)", async () => {
			const config = { ...fiveQuestionConfig, questionCount: 4 };
			const material = await quizProvider.create(createContext, config);
			const correct = material.privateData.correct as string[];
			const threeOfFour = [...correct];
			threeOfFour[0] = "definitely-not-it";
			const result = await quizProvider.verify(verifyContext, config, material.privateData, { choices: threeOfFour });
			expect(result.success).toBe(false);
		});

		test("defaults to requiring 100% when passPercent is omitted", async () => {
			const config = { questions: fiveQuestionConfig.questions, questionCount: 5 };
			const material = await quizProvider.create(createContext, config);
			const correct = material.privateData.correct as string[];
			const fourOfFive = [...correct];
			fourOfFive[0] = "definitely-not-it";
			const result = await quizProvider.verify(verifyContext, config, material.privateData, { choices: fourOfFive });
			expect(result.success).toBe(false);
		});
	});
});
