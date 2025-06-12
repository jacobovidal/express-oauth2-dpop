import type { JtiData } from "../types/types.js";

export abstract class AbstractJtiStore {
  abstract set(identifier: string, data: JtiData): Promise<void>;
  abstract get(identifier: string): Promise<JtiData | undefined>;
  abstract delete(identifier: string): Promise<void>;
}
