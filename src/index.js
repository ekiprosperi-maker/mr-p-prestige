const COOKIE_NAME = "mpp_admin_session";
const SESSION_SECONDS = 60 * 60 * 8;

export default {
async fetch(request, env) {
const url = new URL(request.url);
const path = url.pathname;
const method = request.method;

try {
  if (path.startsWith("/api/")) {
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": url.origin,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    if (path === "/api/health" && method === "GET") {
      return json({ ok: true, store: "Mr P Prestige" });
    }

    if (path === "/api/products" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT id, name, description, price, category, image_url, stock, created_at FROM products ORDER BY created_at DESC"
      ).all();

      return json({ products: results || [] });
    }

    if (path === "/api/login" && method === "POST") {
      if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
        return json({ error: "Admin secrets are not configured." }, 503);
      }

      const body = await request.json();

      if (
        typeof body.password !== "string" ||
        body.password.length > 200 ||
        body.password !== env.ADMIN_PASSWORD
      ) {
        return json({ error: "Incorrect password." }, 401);
      }

      const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
      const token = await sign(`${expires}`, env.SESSION_SECRET);

      return json(
        { ok: true },
        200,
        {
          "Set-Cookie":
            `${COOKIE_NAME}=${expires}.${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`
        }
      );
    }

    if (path === "/api/logout" && method === "POST") {
      return json(
        { ok: true },
        200,
        {
          "Set-Cookie":
            `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
        }
      );
    }

    if (path.startsWith("/api/admin/")) {
      const allowed = await isAdmin(request, env);

      if (!allowed) {
        return json(
          { error: "Please sign in as the administrator." },
          401
        );
      }

      if (path === "/api/admin/products" && method === "POST") {
        const body = await request.json();
        const product = validateProduct(body);

        if (!product) {
          return json(
            { error: "Enter a product name, valid price and category." },
            400
          );
        }

        const id = crypto.randomUUID();

        await env.DB.prepare(
          `INSERT INTO products
          (id, name, description, price, category, image_url, stock, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          id,
          product.name,
          product.description,
          product.price,
          product.category,
          product.image_url,
          product.stock,
          new Date().toISOString()
        ).run();

        return json({ ok: true, id }, 201);
      }

      const productMatch = path.match(
        /^\/api\/admin\/products\/([^/]+)$/
      );

      if (productMatch) {
        const id = productMatch[1];

        if (method === "PUT") {
          const body = await request.json();
          const product = validateProduct(body);

          if (!product) {
            return json(
              { error: "Check the product details and try again." },
              400
            );
          }

          const result = await env.DB.prepare(
            `UPDATE products SET
            name = ?, description = ?, price = ?, category = ?,
            image_url = ?, stock = ?
            WHERE id = ?`
          ).bind(
            product.name,
            product.description,
            product.price,
            product.category,
            product.image_url,
            product.stock,
            id
          ).run();

          if (!result.meta.changes) {
            return json({ error: "Product not found." }, 404);
          }

          return json({ ok: true });
        }

        if (method === "DELETE") {
          const product = await env.DB.prepare(
            "SELECT id FROM products WHERE id = ?"
          ).bind(id).first();

          if (!product) {
            return json({ error: "Product not found." }, 404);
          }

          await env.DB.prepare(
            "DELETE FROM products WHERE id = ?"
          ).bind(id).run();

          return json({ ok: true });
        }
      }

      return json({ error: "Admin route not found." }, 404);
    }

    return json({ error: "API route not found." }, 404);
  }

  return env.ASSETS.fetch(request);
} catch (error) {
  console.error("Request failed:", error);
  return json(
    { error: "Something went wrong. Please try again." },
    500
  );
}

}
};

function json(data, status = 200, extraHeaders = {}) {
return new Response(JSON.stringify(data), {
status,
headers: {
"Content-Type": "application/json; charset=utf-8",
"Cache-Control": "no-store",
"X-Content-Type-Options": "nosniff",
...extraHeaders
}
});
}

function validateProduct(body) {
if (!body || typeof body !== "object") return null;

const name = String(body.name || "").trim();
const category = String(body.category || "").trim();
const description = String(body.description || "").trim();
const price = Number(body.price);
const stock = Number(body.stock ?? 0);
const image_url = String(body.image_url || "").trim();

if (
!name || name.length > 120 ||
!category || category.length > 60 ||
!Number.isFinite(price) || price < 0 ||
!Number.isInteger(stock) || stock < 0 ||
description.length > 2000 ||
image_url.length > 500 ||
(image_url && !/^https:\/\/[^\s]+$/i.test(image_url))
) {
return null;
}

return { name, category, description, price, stock, image_url };
}

async function sign(value, secret) {
const key = await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(secret),
{ name: "HMAC", hash: "SHA-256" },
false,
["sign"]
);

const signature = await crypto.subtle.sign(
"HMAC",
key,
new TextEncoder().encode(value)
);

return btoa(String.fromCharCode(...new Uint8Array(signature)))
.replace(/+/g, "-")
.replace(///g, "_")
.replace(/=+$/g, "");
}

async function isAdmin(request, env) {
if (!env.SESSION_SECRET) return false;

const cookie = request.headers.get("Cookie") || "";
const match = cookie.match(
new RegExp("(?:^|;\\s*)${COOKIE_NAME}=([0-9]+)\\.([A-Za-z0-9_-]+)")
);

if (!match) return false;

const expires = Number(match[1]);

if (
!Number.isSafeInteger(expires) ||
expires <= Date.now() / 1000
) {
return false;
}

const expected = await sign(match[1], env.SESSION_SECRET);

return constantTimeEqual(match[2], expected);
}

function constantTimeEqual(a, b) {
if (a.length !== b.length) return false;

let difference = 0;

for (let i = 0; i < a.length; i++) {
difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
}

return difference === 0;
}