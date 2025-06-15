import type { JtiData } from "../../types/types.js";
import { AbstractJtiStore } from "../../store/abstract-jti-store.js";

export class MockJtiStore extends AbstractJtiStore {
  private store = new Map<string, JtiData>();

  async set(identifier: string, data: JtiData): Promise<void> {
    this.store.set(identifier, data);
  }

  async get(identifier: string): Promise<JtiData | undefined> {
    return this.store.get(identifier);
  }
}
