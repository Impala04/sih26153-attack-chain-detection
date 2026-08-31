import { Analytics } from '@vercel/analytics/next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import type { Metadata, Viewport } from 'next'
import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono-ui' })

export const metadata: Metadata = {
  title: 'SIH26153 — Attack Chain Detection',
  description: 'Predictive Network Security Dashboard for AI-powered threat detection and risk intelligence.',
  generator: 'SIH26153',
}
export const viewport: Viewport = { colorScheme: 'dark', themeColor: '#07101c', userScalable: false }

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" className="bg-background"><body className={`${inter.variable} ${mono.variable} antialiased`}>{children}{process.env.NODE_ENV === 'production' && <Analytics />}</body></html>
}
