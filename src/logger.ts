import { Levels, Logger as RabbitLogger } from "@rabbit-company/web-middleware/logger";
import { dailyFileLogs } from "./services/daily-file-log-service.ts";

export const Logger = new RabbitLogger({ level: dailyFileLogs.loggerLevel() ?? Levels.INFO });
Logger.addTransport(dailyFileLogs);
dailyFileLogs.setLevelHandler((level) => Logger.setLevel(level));
