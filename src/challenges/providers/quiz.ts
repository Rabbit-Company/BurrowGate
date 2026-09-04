import { buildChallengeTemplate } from "../../services/challenge-page-service.ts";
import { hexColorConfig } from "../color-config.ts";
import type { ChallengeProvider } from "../types.ts";

// [data-bg-quiz="progress"|"options"] - "progress" is an optional "Question X of Y" indicator;
// "options" is a fallback container quiz.js creates buttons into at runtime, only used when the
// four hooks below aren't all present.
//
// [data-bg-quiz-option="0"|"1"|"2"|"3"] - up to 4 fixed answer-button slots, all-or-nothing like
// Snake's move hooks: quiz.js reuses these real elements directly (setting their text and a click
// listener, hiding whichever slots a round doesn't need) instead of creating buttons at runtime,
// so each option's position/styling is fully template-editable. The default template below already
// uses this path - there's no separate "default vs custom" behavior in the client script.
const DEFAULT_TEMPLATE = buildChallengeTemplate({
	bodyExtra:
		'<div class="bg-quiz-wrapper">' +
		'<div class="bg-quiz-progress" data-bg-quiz="progress"></div>' +
		'<div class="bg-quiz-options" data-bg-quiz="options">' +
		'<button type="button" class="bg-quiz-option" data-bg-quiz-option="0"></button>' +
		'<button type="button" class="bg-quiz-option" data-bg-quiz-option="1"></button>' +
		'<button type="button" class="bg-quiz-option" data-bg-quiz-option="2"></button>' +
		'<button type="button" class="bg-quiz-option" data-bg-quiz-option="3"></button>' +
		"</div></div>",
});

const MAX_QUESTION_LENGTH = 300;
const MAX_ANSWER_LENGTH = 200;
const MIN_QUESTIONS = 1;
const MAX_QUESTIONS = 50;
const MIN_CORRECT_ANSWERS_PER_QUESTION = 1;
const MAX_CORRECT_ANSWERS_PER_QUESTION = 10;
const MIN_WRONG_ANSWERS_PER_QUESTION = 1;
const MAX_WRONG_ANSWERS_PER_QUESTION = 20;
const MIN_QUESTION_COUNT = 1;
const MAX_QUESTION_COUNT = 20;
const DEFAULT_QUESTION_COUNT = 3;
const MAX_WRONG_OPTIONS_PER_QUESTION = 3;
const MIN_PASS_PERCENT = 1;
const MAX_PASS_PERCENT = 100;
const DEFAULT_PASS_PERCENT = 100;
const DEFAULT_OPTION_COLOR = "#0f172a";
const DEFAULT_OPTION_BORDER_COLOR = "#202d4b";
const DEFAULT_OPTION_TEXT_COLOR = "#e5e7eb";
const DEFAULT_ACCENT_COLOR = "#7c3aed";

interface QaEntry {
	question: string;
	correctAnswers: string[];
	wrongAnswers: string[];
}

function randomInt(maxExclusive: number): number {
	return crypto.getRandomValues(new Uint32Array(1))[0]! % maxExclusive;
}

function pickRandom<T>(arr: T[], n: number): T[] {
	const copy = [...arr];
	const out: T[] = [];
	for (let i = 0; i < n && copy.length > 0; i++) {
		const idx = randomInt(copy.length);
		out.push(copy.splice(idx, 1)[0]!);
	}
	return out;
}

function shuffle<T>(arr: T[]): T[] {
	const copy = [...arr];
	for (let i = copy.length - 1; i > 0; i--) {
		const j = randomInt(i + 1);
		[copy[i], copy[j]] = [copy[j]!, copy[i]!];
	}
	return copy;
}

function parseQaEntry(raw: unknown, index: number): QaEntry {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
		throw new Error(`Question ${index + 1} must be an object`);
	}
	const record = raw as Record<string, unknown>;

	const question = String(record.question ?? "").trim();
	if (!question || question.length > MAX_QUESTION_LENGTH) {
		throw new Error(`Question ${index + 1} text must be 1 to ${MAX_QUESTION_LENGTH} characters`);
	}

	const rawCorrect = record.correctAnswers;
	if (!Array.isArray(rawCorrect)) throw new Error(`Question ${index + 1} correct answers must be a list`);
	const correctAnswers = [...new Set(rawCorrect.map((entry) => String(entry ?? "").trim()).filter(Boolean))];
	if (correctAnswers.length < MIN_CORRECT_ANSWERS_PER_QUESTION || correctAnswers.length > MAX_CORRECT_ANSWERS_PER_QUESTION) {
		throw new Error(`Question ${index + 1} must have ${MIN_CORRECT_ANSWERS_PER_QUESTION} to ${MAX_CORRECT_ANSWERS_PER_QUESTION} correct answers`);
	}
	for (const value of correctAnswers) {
		if (value.length > MAX_ANSWER_LENGTH) throw new Error(`Question ${index + 1}'s correct answers must be at most ${MAX_ANSWER_LENGTH} characters`);
	}

	const rawWrong = record.wrongAnswers;
	if (!Array.isArray(rawWrong)) throw new Error(`Question ${index + 1} wrong answers must be a list`);
	const wrongAnswers = [...new Set(rawWrong.map((entry) => String(entry ?? "").trim()).filter(Boolean))].filter((value) => !correctAnswers.includes(value));
	if (wrongAnswers.length < MIN_WRONG_ANSWERS_PER_QUESTION || wrongAnswers.length > MAX_WRONG_ANSWERS_PER_QUESTION) {
		throw new Error(`Question ${index + 1} must have ${MIN_WRONG_ANSWERS_PER_QUESTION} to ${MAX_WRONG_ANSWERS_PER_QUESTION} wrong answers`);
	}
	for (const value of wrongAnswers) {
		if (value.length > MAX_ANSWER_LENGTH) throw new Error(`Question ${index + 1}'s wrong answers must be at most ${MAX_ANSWER_LENGTH} characters`);
	}

	return { question, correctAnswers, wrongAnswers };
}

function questionsConfig(config: Record<string, unknown>): QaEntry[] {
	const raw = config.questions;
	if (!Array.isArray(raw)) throw new Error("Questions must be a list");
	if (raw.length < MIN_QUESTIONS || raw.length > MAX_QUESTIONS) {
		throw new Error(`Questions must contain ${MIN_QUESTIONS} to ${MAX_QUESTIONS} entries`);
	}
	return raw.map(parseQaEntry);
}

function questionCountConfig(config: Record<string, unknown>): number {
	if (config.questionCount === undefined) return DEFAULT_QUESTION_COUNT;
	const value = Number(config.questionCount);
	if (!Number.isInteger(value) || value < MIN_QUESTION_COUNT || value > MAX_QUESTION_COUNT) {
		throw new Error(`Question count must be an integer from ${MIN_QUESTION_COUNT} to ${MAX_QUESTION_COUNT}`);
	}
	return value;
}

function passPercentConfig(config: Record<string, unknown>): number {
	if (config.passPercent === undefined) return DEFAULT_PASS_PERCENT;
	const value = Number(config.passPercent);
	if (!Number.isInteger(value) || value < MIN_PASS_PERCENT || value > MAX_PASS_PERCENT) {
		throw new Error(`Pass threshold must be an integer percentage from ${MIN_PASS_PERCENT} to ${MAX_PASS_PERCENT}`);
	}
	return value;
}

export const quizProvider: ChallengeProvider = {
	name: "quiz",
	clientScript: "/_burrowgate/static/challenges/quiz.js",
	title: "Answer a few questions",
	description: "This website asks visitors to answer a few multiple-choice questions before continuing.",
	defaultHtmlTemplate: DEFAULT_TEMPLATE,

	defaultTexts: [{ key: "wrongAnswer", label: "Wrong answer message", default: "That's not quite right - try again." }],

	validateConfig(config) {
		questionsConfig(config);
		questionCountConfig(config);
		passPercentConfig(config);
		hexColorConfig(config, "optionColor", DEFAULT_OPTION_COLOR);
		hexColorConfig(config, "optionBorderColor", DEFAULT_OPTION_BORDER_COLOR);
		hexColorConfig(config, "optionTextColor", DEFAULT_OPTION_TEXT_COLOR);
		hexColorConfig(config, "accentColor", DEFAULT_ACCENT_COLOR);
	},

	async create(_context, config) {
		const questions = questionsConfig(config);
		const count = Math.min(questionCountConfig(config), questions.length);
		const chosen = pickRandom(questions, count);

		const rounds: { question: string; options: string[] }[] = [];
		const correct: string[] = [];
		for (const entry of chosen) {
			const correctAnswer = pickRandom(entry.correctAnswers, 1)[0]!;
			const wrongs = pickRandom(entry.wrongAnswers, Math.min(MAX_WRONG_OPTIONS_PER_QUESTION, entry.wrongAnswers.length));
			rounds.push({ question: entry.question, options: shuffle([correctAnswer, ...wrongs]) });
			correct.push(correctAnswer);
		}

		return {
			publicData: {
				kind: "quiz",
				rounds,
				optionColor: hexColorConfig(config, "optionColor", DEFAULT_OPTION_COLOR),
				optionBorderColor: hexColorConfig(config, "optionBorderColor", DEFAULT_OPTION_BORDER_COLOR),
				optionTextColor: hexColorConfig(config, "optionTextColor", DEFAULT_OPTION_TEXT_COLOR),
				accentColor: hexColorConfig(config, "accentColor", DEFAULT_ACCENT_COLOR),
			},
			privateData: { correct },
		};
	},

	async verify(_context, config, privateData, answer) {
		const answerObject = answer && typeof answer === "object" ? (answer as Record<string, unknown>) : {};
		const submitted = Array.isArray(answerObject.choices) ? answerObject.choices : null;
		const correct = Array.isArray(privateData.correct) ? privateData.correct : [];

		if (!submitted || submitted.length !== correct.length || correct.length === 0) {
			return { success: false, reason: "wrongAnswer" };
		}
		const correctCount = submitted.filter((choice, index) => typeof choice === "string" && choice === correct[index]).length;
		const requiredCorrect = Math.ceil((passPercentConfig(config) / 100) * correct.length);
		if (correctCount < requiredCorrect) {
			return { success: false, reason: "wrongAnswer" };
		}

		return { success: true, metadata: { provider: "quiz", questionCount: correct.length, correctCount } };
	},
};
