import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const store = getStore("bnd-fan-database");

const COOKIE_NAME = "bnd_admin_session";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers
    }
  });
}

function makeToken(username) {
  const secret = process.env.ADMIN_SECRET;

  if (!secret) {
    throw new Error("ADMIN_SECRET 尚未設定");
  }

  const payload = Buffer.from(
    JSON.stringify({
      username,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(token) {
  try {
    if (!token) return false;

    const secret = process.env.ADMIN_SECRET;
    if (!secret) return false;

    const parts = token.split(".");

    if (parts.length !== 2) return false;

    const [payload, signature] = parts;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    if (signature !== expected) {
      return false;
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (Date.now() > data.exp) {
      return false;
    }

    return true;

  } catch {
    return false;
  }
}

function getCookie(request) {
  const cookies = request.headers.get("cookie") || "";

  const match = cookies.match(
    new RegExp("(?:^|; )" + COOKIE_NAME + "=([^;]*)")
  );

  return match ? match[1] : null;
}

function authorized(request) {
  return verifyToken(getCookie(request));
}

const defaultData = {
  memory: [],
  members: [],
  albums: [],
  stages: [],
  social: [],
  languages: {
    "zh-Hant": {},
    "zh-Hans": {},
    "en": {},
    "ja": {},
    "ko": {}
  }
};

export default async function handler(request) {
  try {

    if (request.method === "GET") {

      if (!authorized(request)) {
        return json({ message: "未登入" }, 401);
      }

      const data = await store.get(
        "site-data",
        { type: "json" }
      );

      return json({
        data: data || defaultData
      });
    }

    if (request.method === "POST") {

      const body = await request.json();

      if (body.action === "login") {

        const correctUsername =
          process.env.ADMIN_USERNAME;

        const correctPassword =
          process.env.ADMIN_PASSWORD;

        if (!correctUsername || !correctPassword) {
          return json(
            { message: "管理員帳號尚未設定。" },
            500
          );
        }

        if (
          body.username !== correctUsername ||
          body.password !== correctPassword
        ) {
          return json(
            { message: "帳號或密碼錯誤。" },
            401
          );
        }

        const token = makeToken(body.username);

        return json(
          { message: "登入成功" },
          200,
          {
            "Set-Cookie":
              `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
          }
        );
      }

      if (body.action === "logout") {

        return json(
          { message: "已登出" },
          200,
          {
            "Set-Cookie":
              `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
          }
        );
      }

      if (body.action === "save") {

        if (!authorized(request)) {
          return json(
            { message: "未登入" },
            401
          );
        }

        await store.setJSON(
          "site-data",
          body.data
        );

        return json({
          message: "資料已儲存"
        });
      }
    }

    return json(
      { message: "找不到這個請求" },
      404
    );

  } catch (error) {

    console.error(error);

    return json(
      { message: "伺服器發生錯誤" },
      500
    );
  }
}

export const config = {
  path: "/api/admin"
};
