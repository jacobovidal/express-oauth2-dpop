import { AbstractJtiStore } from "express-oauth2-dpop";
import type { JtiData } from "express-oauth2-dpop";
import { createClient } from "redis";

const client = createClient({
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
  },
});

await client.connect();

export class RedisJtiStore extends AbstractJtiStore {
  async set(identifier: string, data: JtiData): Promise<void> {    
    client.set(identifier, JSON.stringify(data), {
      expiration: {
        type: "EXAT",
        value: data.expiresAt,
      }
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
