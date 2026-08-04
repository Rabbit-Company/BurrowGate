import { Levels, Logger as RabbitLogger } from "@rabbit-company/web-middleware/logger";

export const Logger = new RabbitLogger({ level: Levels.INFO });
