import { Scanner } from "./scanner";

export default function Home() {
  return (
    <main>
      <div className="hero">
        <h1>
          Find the leaks in your <span>vibe-coded</span> app 🤠
        </h1>
        <p>
          Paste a URL. leakboy reads what your app ships to every visitor and tells you, in plain words, what anyone can
          already see: open Supabase tables, open Firebase rules, API keys in the bundle, public source maps, exposed{" "}
          <code>.env</code> and <code>.git</code>.
        </p>
      </div>
      <Scanner />
      <section className="how">
        <div>
          <h3>🔑 Secrets in the bundle</h3>
          <p>30+ secret types: Supabase service_role, Stripe, OpenAI, Anthropic, Gemini, AWS, GitHub, Midtrans, Xendit, database URLs… all masked.</p>
        </div>
        <div>
          <h3>🗄️ Supabase RLS</h3>
          <p>Uses only your public anon key to check which tables, buckets and sign-up settings are open to everyone. Prints row counts, never rows.</p>
        </div>
        <div>
          <h3>🔥 Firebase rules</h3>
          <p>Realtime Database, Firestore and Storage: is anything readable without logging in?</p>
        </div>
        <div>
          <h3>📂 Exposed files</h3>
          <p>
            <code>.env</code>, <code>.git</code>, SQL dumps, source maps and missing security headers.
          </p>
        </div>
      </section>
      <section className="cli">
        <h2>Run it locally or in CI</h2>
        <pre>{`npx leakboy https://myapp.vercel.app
npx leakboy ./dist                  # check a build before deploying
npx leakboy myapp.com --fail-under 80 --sarif leakboy.sarif`}</pre>
      </section>
      <footer>
        leakboy is passive and read-only: it never writes data, never shows row contents and masks every secret. Only
        scan apps you own or are allowed to test. ·{" "}
        <a href="https://github.com/Emil-02/leakboy">GitHub</a> · MIT · by{" "}
        <a href="https://github.com/Emil-02">Emil-02</a>
      </footer>
    </main>
  );
}
