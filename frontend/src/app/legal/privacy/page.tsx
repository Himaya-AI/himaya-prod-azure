import Link from 'next/link'

export const metadata = {
  title: 'Privacy Policy — Himaya Technologies Group Inc.',
}

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#e4e4e7] flex flex-col">
      {/* Header */}
      <header className="border-b border-[#27272a] px-6 py-4 flex items-center justify-between">
        <Link href="/login" className="flex items-center gap-2">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/himaya-logo.png" alt="Himaya" className="h-7 w-auto" />
          <span className="text-sm font-semibold text-[#a1a1aa]">Himaya Technologies Group Inc.</span>
        </Link>
        <Link href="/login" className="text-xs text-[#52525b] hover:text-[#a1a1aa] transition-colors">
          ← Back to sign in
        </Link>
      </header>

      {/* Content */}
      <main className="flex-1 max-w-3xl mx-auto w-full px-6 py-12">
        <h1 className="text-2xl font-bold text-white mb-2">Privacy Policy</h1>
        <p className="text-xs text-[#52525b] mb-10">Effective Date: April 11, 2026</p>

        <section className="space-y-8 text-sm leading-relaxed text-[#a1a1aa]">

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">1. What We Collect</h2>
            <p>When you create an account or sign in to the Himaya platform, we collect:</p>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Your <strong className="text-[#e4e4e7]">email address</strong> — used solely to identify your account and send essential service communications</li>
              <li>Basic usage metadata — such as login timestamps and feature access logs</li>
            </ul>
            <p className="mt-2">We do <strong className="text-[#e4e4e7]">not</strong> collect sensitive personal data beyond what is strictly necessary for account management and service operation.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">2. How We Use Your Email</h2>
            <p>Your email address is used to:</p>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Authenticate your account and maintain your session</li>
              <li>Send security-related notifications (e.g., password resets, access alerts)</li>
              <li>Deliver product updates and service announcements, if you have opted in</li>
            </ul>
            <p className="mt-2">We do <strong className="text-[#e4e4e7]">not</strong> sell, rent, or share your email address with third parties for marketing or advertising purposes.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">3. Email Security Analysis</h2>
            <p>The Himaya platform processes email metadata (sender addresses, domains, IP addresses, and attachment hashes) to perform threat detection and policy enforcement. This data is processed within your organization's tenant and is not used to train models or shared externally except where required to perform the service (e.g., threat intelligence lookups).</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">4. Data Retention</h2>
            <p>Account and operational data is retained for the duration of your active subscription. Upon account termination, personal data is deleted within 30 days, subject to any applicable legal obligations requiring longer retention.</p>
            <p className="mt-2">You may request deletion of your account at any time by contacting us at <a href="mailto:legal@himaya.ai" className="text-[#e4e4e7] underline hover:text-white transition-colors">legal@himaya.ai</a>.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">5. Security</h2>
            <p>We use industry-standard security practices to protect your data, including TLS encryption in transit and hashed credential storage at rest. Access to personal data is restricted to authorized personnel only.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">6. Your Rights</h2>
            <p>Depending on your jurisdiction, you may have rights to access, correct, or delete your personal data. To exercise any of these rights, contact us at <a href="mailto:legal@himaya.ai" className="text-[#e4e4e7] underline hover:text-white transition-colors">legal@himaya.ai</a>.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">7. Changes to This Policy</h2>
            <p>We may update this Privacy Policy from time to time. Material changes will be communicated via email or an in-app notice. Continued use of the platform after changes constitutes your acceptance of the updated policy.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">8. Contact</h2>
            <p>For privacy-related questions or concerns, please contact:</p>
            <p className="mt-2">
              <strong className="text-[#e4e4e7]">Himaya Technologies Group Inc.</strong><br />
              <a href="mailto:legal@himaya.ai" className="text-[#e4e4e7] underline hover:text-white transition-colors">legal@himaya.ai</a>
            </p>
          </div>

        </section>
      </main>

      <footer className="border-t border-[#27272a] px-6 py-4 text-center text-xs text-[#3f3f46]">
        © {new Date().getFullYear()} Himaya Technologies Group Inc. All rights reserved.
      </footer>
    </div>
  )
}
