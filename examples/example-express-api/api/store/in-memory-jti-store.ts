import { AbstractJtiStore } from "express-oauth2-dpop";
import type { JtiData } from "express-oauth2-dpop";

export class InMemoryJtiStore extends AbstractJtiStore {
  private store: Map<string, JtiData> = new Map();

  constructor() {
    super();
    setInterval(() => {
      void this.deleteExpired();
    }, 60 * 1000);
  }

  async set(identifier: string, data: JtiData): Promise<void> {
    this.store.set(identifier, data);
  }

  async get(identifier: string): Promise<JtiData | undefined> {
    return this.store.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.store.delete(identifier);
  }

  async deleteExpired(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    for (const [identifier, data] of this.store.entries()) {
      if (data.expiresAt <= now) {
        this.store.delete(identifier);
      }
    }
  }
}
