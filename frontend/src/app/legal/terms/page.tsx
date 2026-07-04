import Link from 'next/link'

export const metadata = {
  title: 'Terms of Service — Himaya Technologies Group Inc.',
}

export default function TermsOfServicePage() {
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
        <h1 className="text-2xl font-bold text-white mb-2">Terms of Service</h1>
        <p className="text-xs text-[#52525b] mb-10">Effective Date: April 11, 2026</p>

        <section className="space-y-8 text-sm leading-relaxed text-[#a1a1aa]">

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">1. Acceptance</h2>
            <p>By accessing or using the Himaya platform operated by <strong className="text-[#e4e4e7]">Himaya Technologies Group Inc.</strong> ("Himaya," "we," "us"), you agree to be bound by these Terms of Service. If you do not agree, you must not access or use the platform.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">2. Permitted Use</h2>
            <p>The Himaya platform is intended for use by authorized security professionals within your organization. By using the platform, you agree to:</p>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Use the platform only for lawful purposes and in accordance with your organization's security policies</li>
              <li>Not share your account credentials with other individuals</li>
              <li>Not attempt to reverse-engineer, scrape, or abuse the platform's infrastructure or APIs</li>
              <li>Not use the platform to process data you are not authorized to handle</li>
            </ul>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">3. Account Responsibility</h2>
            <p>You are responsible for maintaining the confidentiality of your login credentials. You must notify us immediately at <a href="mailto:legal@himaya.ai" className="text-[#e4e4e7] underline hover:text-white transition-colors">legal@himaya.ai</a> if you become aware of any unauthorized access to or use of your account.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">4. Intellectual Property</h2>
            <p>All platform content, software, tooling, and data provided through Himaya remain the sole property of Himaya Technologies Group Inc. or its licensors. Unauthorized reproduction, redistribution, or commercial exploitation of any platform content is strictly prohibited.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">5. Threat Intelligence Data</h2>
            <p>Threat intelligence data surfaced by the platform (including IOC feeds, blocklists, and detection results) is provided for informational and operational security purposes only. Himaya makes no warranty as to the completeness or accuracy of threat data. You are solely responsible for decisions made based on platform output.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">6. Limitation of Liability</h2>
            <p>The platform is provided "as-is" without warranties of any kind, express or implied. To the fullest extent permitted by applicable law, Himaya Technologies Group Inc. shall not be liable for any indirect, incidental, consequential, or punitive damages arising from or related to your use of — or inability to use — the platform.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">7. Suspension and Termination</h2>
            <p>We reserve the right to suspend or terminate your access to the platform at any time if we reasonably believe you have violated these Terms or if required by law.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">8. Changes to Terms</h2>
            <p>We may revise these Terms at any time. Where changes are material, we will notify you via email or an in-app notice with reasonable advance notice. Continued use of the platform after the effective date of revised Terms constitutes your acceptance.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">9. Governing Law</h2>
            <p>These Terms are governed by the laws of the jurisdiction in which Himaya Technologies Group Inc. is incorporated, without regard to conflict-of-law principles.</p>
          </div>

          <div>
            <h2 className="text-base font-semibold text-[#e4e4e7] mb-2">10. Contact</h2>
            <p>For legal inquiries or questions about these Terms, please contact:</p>
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
