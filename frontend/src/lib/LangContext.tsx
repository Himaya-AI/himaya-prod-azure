'use client'
import React, { createContext, useContext, useEffect, useState } from 'react'
import { getLang, setLangGlobal, type Lang } from './i18n'

interface LangCtx {
  lang: Lang
  setLang: (l: Lang) => void
  isRtl: boolean
}

const LangContext = createContext<LangCtx>({ lang: 'en', setLang: () => {}, isRtl: false })

export function LangProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>('en')

  useEffect(() => {
    // Init from localStorage
    const saved = getLang()
    setLangState(saved)
    // Apply to DOM
    document.documentElement.setAttribute('dir', saved === 'ar' ? 'rtl' : 'ltr')
    document.documentElement.setAttribute('lang', saved)

    // Listen for changes from TopBar toggle
    const handler = (e: Event) => {
      const l = (e as CustomEvent<Lang>).detail
      setLangState(l)
    }
    window.addEventListener('lang-change', handler)
    return () => window.removeEventListener('lang-change', handler)
  }, [])

  const setLang = (l: Lang) => {
    setLangGlobal(l)
    setLangState(l)
  }

  return (
    <LangContext.Provider value={{ lang, setLang, isRtl: lang === 'ar' }}>
      {children}
    </LangContext.Provider>
  )
}

export function useLang() {
  return useContext(LangContext)
}
