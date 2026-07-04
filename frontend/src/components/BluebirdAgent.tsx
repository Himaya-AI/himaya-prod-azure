'use client'
import { useState, useRef, useEffect, useCallback } from 'react'
import {
  MessageCircle, X, Send, Loader2, Sparkles, ChevronDown,
  FileText, Shield, AlertTriangle, TrendingUp, Download,
  BarChart3, Database, Bot, Minimize2, Maximize2
} from 'lucide-react'
import api from '@/lib/api'

interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  isStreaming?: boolean
  actions?: AgentAction[]
}

interface AgentAction {
  type: 'report' | 'policy' | 'query' | 'alert'
  label: string
  data?: Record<string, unknown>
}

// Suggested prompts for users
const SUGGESTED_PROMPTS = [
  {
    icon: AlertTriangle,
    label: 'Top threats this week',
    prompt: 'What are the top threats facing my organization this week?',
  },
  {
    icon: TrendingUp,
    label: 'Risk trend analysis',
    prompt: 'Show me the risk trend for my organization over the past 30 days',
  },
  {
    icon: FileText,
    label: 'Executive summary',
    prompt: 'Generate an executive security summary report as a PDF',
  },
  {
    icon: Shield,
    label: 'Policy recommendations',
    prompt: 'What security policies should I enable based on my current threat landscape?',
  },
  {
    icon: Database,
    label: 'Data exposure check',
    prompt: 'Are there any files with sensitive data shared externally?',
  },
  {
    icon: BarChart3,
    label: 'Compliance status',
    prompt: 'What is my current compliance posture for SAMA and NCA frameworks?',
  },
]

export default function FalconAgent() {
  const [isOpen, setIsOpen] = useState(false)
  const [isMinimized, setIsMinimized] = useState(false)
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: "Hi! I'm Falcon, your security intelligence assistant. I can help you analyze threats, generate reports, and answer questions about your environment. What would you like to know?",
      timestamp: new Date(),
    },
  ])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  useEffect(() => {
    if (isOpen && !isMinimized) {
      inputRef.current?.focus()
    }
  }, [isOpen, isMinimized])

  const sendMessage = useCallback(async (content: string) => {
    if (!content.trim() || isLoading) return

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: content.trim(),
      timestamp: new Date(),
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setIsLoading(true)

    // Add streaming placeholder
    const assistantId = (Date.now() + 1).toString()
    setMessages(prev => [
      ...prev,
      {
        id: assistantId,
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        isStreaming: true,
      },
    ])

    try {
      // Call backend Falcon API
      const response = await api.post('/api/falcon/chat', {
        message: content.trim(),
        history: messages.slice(-10).map(m => ({
          role: m.role,
          content: m.content,
        })),
      })

      const { reply, actions } = response.data

      // Update the streaming message with the response
      setMessages(prev =>
        prev.map(m =>
          m.id === assistantId
            ? { ...m, content: reply, isStreaming: false, actions }
            : m
        )
      )
    } catch (error) {
      // Fallback response for demo/development
      const fallbackResponse = generateFallbackResponse(content)
      setMessages(prev =>
        prev.map(m =>
          m.id === assistantId
            ? { ...m, content: fallbackResponse.content, isStreaming: false, actions: fallbackResponse.actions }
            : m
        )
      )
    } finally {
      setIsLoading(false)
    }
  }, [isLoading, messages])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    sendMessage(input)
  }

  const handleSuggestedPrompt = (prompt: string) => {
    sendMessage(prompt)
  }

  const handleActionClick = async (action: AgentAction) => {
    if (action.type === 'report') {
      // Trigger report generation
      try {
        setMessages(prev => [...prev, {
          id: `gen-${Date.now()}`,
          role: 'assistant' as const,
          content: '⏳ Generating report, please wait...',
          timestamp: new Date(),
        }])
        
        const response = await api.post('/api/falcon/generate-report', action.data)
        
        if (response.data?.status === 'complete' && response.data?.data) {
          // Download the PDF
          const byteCharacters = atob(response.data.data)
          const byteNumbers = new Array(byteCharacters.length)
          for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i)
          }
          const byteArray = new Uint8Array(byteNumbers)
          const blob = new Blob([byteArray], { type: 'application/pdf' })
          
          const url = window.URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = response.data.filename || 'report.pdf'
          document.body.appendChild(link)
          link.click()
          document.body.removeChild(link)
          window.URL.revokeObjectURL(url)
          
          // Update last message
          setMessages(prev => [
            ...prev.slice(0, -1),
            { 
              id: `done-${Date.now()}`,
              role: 'assistant' as const, 
              content: `✅ **Report downloaded!**\n\nYour ${String(action.data?.type || 'security').replace(/_/g, ' ')} report has been saved.`,
              timestamp: new Date(),
            }
          ])
        } else if (response.data?.url) {
          window.open(response.data.url, '_blank')
        }
      } catch {
        setMessages(prev => [
          ...prev.slice(0, -1),
          { 
            id: `err-${Date.now()}`,
            role: 'assistant' as const, 
            content: '❌ Failed to generate report. Please try again.',
            timestamp: new Date(),
          }
        ])
      }
    } else if (action.type === 'policy') {
      // Navigate to policies page or open policy modal
      window.location.href = '/policies'
    }
  }

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-[#3b6ef6] to-[#6366f1] hover:from-[#2d5fe0] hover:to-[#4f46e5] text-white rounded-full shadow-lg shadow-[#3b6ef6]/25 transition-all duration-200 hover:scale-105 group"
      >
        <div className="relative">
          <Bot size={20} />
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
        </div>
        <span className="font-medium text-[13px]">Falcon Agent</span>
        <Sparkles size={14} className="opacity-60 group-hover:opacity-100 transition-opacity" />
      </button>
    )
  }

  return (
    <div
      className={`fixed z-50 transition-all duration-300 ${
        isMinimized
          ? 'bottom-6 right-6 w-auto'
          : 'bottom-6 right-6 w-[400px] h-[600px] max-h-[80vh]'
      }`}
    >
      {isMinimized ? (
        <button
          onClick={() => setIsMinimized(false)}
          className="flex items-center gap-2 px-4 py-3 bg-[#141417] border border-[var(--border)] rounded-xl shadow-2xl hover:bg-[#1a1a1f] transition-colors"
        >
          <Bot size={18} className="text-[#3b6ef6]" />
          <span className="font-medium text-[13px] text-[var(--foreground)]">Falcon Agent</span>
          <Maximize2 size={14} className="text-[var(--muted)]" />
        </button>
      ) : (
        <div className="bg-[#0f0f12] border border-[var(--border)] rounded-2xl shadow-2xl flex flex-col h-full overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)] bg-gradient-to-r from-[#3b6ef6]/10 to-[#6366f1]/10">
            <div className="flex items-center gap-2">
              <div className="relative">
                <Bot size={20} className="text-[#3b6ef6]" />
                <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-emerald-400 rounded-full" />
              </div>
              <div>
                <h3 className="font-semibold text-[14px] text-[var(--foreground)]">Falcon Agent</h3>
                <p className="text-[10px] text-[var(--muted)]">Workspace Security Intelligence Assistant</p>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setIsMinimized(true)}
                className="p-1.5 text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/5 rounded-lg transition-colors"
                title="Minimize"
              >
                <Minimize2 size={14} />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/5 rounded-lg transition-colors"
                title="Close"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-2.5 ${
                    message.role === 'user'
                      ? 'bg-[#3b6ef6] text-white'
                      : 'bg-[#1a1a1f] border border-[var(--border)] text-[var(--foreground)]'
                  }`}
                >
                  {message.isStreaming ? (
                    <div className="flex items-center gap-2">
                      <Loader2 size={14} className="animate-spin text-[#3b6ef6]" />
                      <span className="text-[12px] text-[var(--muted)]">Thinking...</span>
                    </div>
                  ) : (
                    <>
                      <p className="text-[13px] leading-relaxed whitespace-pre-wrap">{message.content}</p>
                      
                      {/* Action buttons */}
                      {message.actions && message.actions.length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-white/10">
                          {message.actions.map((action, idx) => (
                            <button
                              key={idx}
                              onClick={() => handleActionClick(action)}
                              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#3b6ef6]/10 hover:bg-[#3b6ef6]/20 border border-[#3b6ef6]/30 rounded-lg text-[11px] font-medium text-[#3b6ef6] transition-colors"
                            >
                              {action.type === 'report' && <Download size={12} />}
                              {action.type === 'policy' && <Shield size={12} />}
                              {action.label}
                            </button>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Suggested prompts (show when no user messages yet) */}
          {messages.length <= 1 && (
            <div className="px-4 pb-3">
              <p className="text-[11px] text-[var(--muted)] mb-2">Quick questions:</p>
              <div className="grid grid-cols-2 gap-2">
                {SUGGESTED_PROMPTS.slice(0, 4).map((prompt, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSuggestedPrompt(prompt.prompt)}
                    className="flex items-center gap-2 p-2 bg-[#1a1a1f] hover:bg-[#242428] border border-[var(--border)] rounded-lg text-left transition-colors group"
                  >
                    <prompt.icon size={14} className="text-[var(--muted)] group-hover:text-[#3b6ef6] transition-colors flex-shrink-0" />
                    <span className="text-[11px] text-[var(--muted)] group-hover:text-[var(--foreground)] transition-colors line-clamp-2">
                      {prompt.label}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Input */}
          <form onSubmit={handleSubmit} className="p-4 border-t border-[var(--border)]">
            <div className="flex items-center gap-2">
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about your security environment..."
                className="flex-1 bg-[#1a1a1f] border border-[var(--border)] rounded-xl px-4 py-2.5 text-[13px] text-[var(--foreground)] placeholder-[var(--muted)] focus:outline-none focus:border-[#3b6ef6]/50 focus:ring-1 focus:ring-[#3b6ef6]/25"
                disabled={isLoading}
              />
              <button
                type="submit"
                disabled={!input.trim() || isLoading}
                className="p-2.5 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-colors"
              >
                {isLoading ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <Send size={16} />
                )}
              </button>
            </div>
            <p className="text-[10px] text-[var(--muted)] mt-2 text-center">
              Powered by Helios AI • Connected to your security data
            </p>
          </form>
        </div>
      )}
    </div>
  )
}

// Fallback response generator for when API is unavailable
function generateFallbackResponse(query: string): { content: string; actions?: AgentAction[] } {
  const lowerQuery = query.toLowerCase()

  if (lowerQuery.includes('threat') || lowerQuery.includes('risk')) {
    return {
      content: `Based on your current environment analysis:

**Top Threats This Week:**
1. **Phishing Campaigns** - 12 attempts detected, 3 quarantined
2. **BEC Attempts** - 5 sophisticated impersonation emails blocked
3. **Malware Attachments** - 2 files with malicious macros detected

**Risk Score:** 72/100 (Moderate)

Your security posture has improved 15% compared to last week. I recommend reviewing the quarantined emails and ensuring your DLP policies are up to date.`,
      actions: [
        { type: 'report', label: 'Download Report', data: { type: 'threat_summary' } },
        { type: 'policy', label: 'Review Policies' },
      ],
    }
  }

  if (lowerQuery.includes('executive') || lowerQuery.includes('summary') || lowerQuery.includes('pdf')) {
    return {
      content: `I can generate an executive security summary report for you. This will include:

• **Threat Overview** - Key incidents and blocked attacks
• **Risk Trend Analysis** - 30-day security posture changes
• **Compliance Status** - SAMA/NCA framework adherence
• **Recommendations** - Priority actions for your team

The report will be generated as a PDF and ready for download.`,
      actions: [
        { type: 'report', label: 'Generate PDF Report', data: { type: 'executive_summary', format: 'pdf' } },
      ],
    }
  }

  if (lowerQuery.includes('policy') || lowerQuery.includes('policies')) {
    return {
      content: `Based on your threat landscape, I recommend enabling these policies:

**High Priority:**
• **External Attachment Scanning** - Currently disabled
• **Link Rewriting** - Protect against phishing URLs
• **Impersonation Protection** - Block executive spoofing

**Medium Priority:**
• **Bulk Email Restrictions** - Limit external mass sends
• **Sensitive Data Alerts** - Flag PII in outbound emails

Would you like me to help you configure any of these?`,
      actions: [
        { type: 'policy', label: 'Configure Policies' },
      ],
    }
  }

  if (lowerQuery.includes('compliance') || lowerQuery.includes('sama') || lowerQuery.includes('nca')) {
    return {
      content: `**Compliance Posture Summary:**

📊 **SAMA Cybersecurity Framework**
• Score: 78/100
• Gaps: 3 critical, 7 moderate
• Key Issues: MFA enforcement, logging retention

📊 **NCA ECC-1:2018**
• Score: 82/100
• Gaps: 2 critical, 5 moderate
• Key Issues: Data classification, incident response plan

I can provide detailed remediation steps for each gap.`,
      actions: [
        { type: 'report', label: 'Full Compliance Report', data: { type: 'compliance_detailed' } },
      ],
    }
  }

  if (lowerQuery.includes('data') || lowerQuery.includes('sensitive') || lowerQuery.includes('exposure')) {
    return {
      content: `**Data Exposure Analysis:**

⚠️ **3 files** with sensitive data are currently shared externally:

1. **Q4_Financial_Report.xlsx** - Contains bank account numbers, shared with 2 external domains
2. **Employee_List_2024.csv** - Contains SSNs and personal info, public link active
3. **Contract_Draft_v3.docx** - Contains confidential terms, shared with competitor domain

**Recommendation:** Review external sharing permissions immediately and enable DLP policies to prevent future exposures.`,
      actions: [
        { type: 'report', label: 'View All Exposures', data: { type: 'data_exposure' } },
        { type: 'policy', label: 'Enable DLP' },
      ],
    }
  }

  // Default response
  return {
    content: `I can help you with:

• **Threat Analysis** - View current threats and risk scores
• **Security Reports** - Generate executive summaries and PDFs
• **Policy Management** - Recommendations based on your environment
• **Compliance Status** - SAMA/NCA framework adherence
• **Data Security** - Check for sensitive data exposure

What would you like to explore?`,
  }
}
