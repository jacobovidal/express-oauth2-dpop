import { AbstractJtiStore } from "express-oauth2-dpop";
import { createClient } from "redis";
import type { JtiData } from "express-oauth2-dpop";

const client = await createClient({
  url: process.env.REDIS_URL,
}).connect();

export class RedisJtiStore extends AbstractJtiStore {
  async set(identifier: string, data: JtiData): Promise<void> {
    client.set(identifier, JSON.stringify(data), {
      expiration: {
        type: "EXAT",
        value: data.expiresAt,
      },
    });
  }

  async get(identifier: string): Promise<JtiData | undefined> {
    const data = await client.get(identifier);

    if (!data) {
      return undefined;
    }

    return JSON.parse(data) as JtiData;
  }
}
