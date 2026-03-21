import { Link, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'

const navItems = [
  { path: '/', label: 'Campaigns' },
  { path: '/tools', label: 'Tools' },
  { path: '/ai', label: 'AI Agents' },
]

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-ice-900 border-b border-gray-700 px-6 py-3 flex items-center gap-8">
        <Link to="/" className="text-xl font-bold text-red-500 tracking-tight">
          ice_9
        </Link>
        <nav className="flex gap-4">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`text-sm px-3 py-1 rounded ${
                location.pathname === item.path
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </header>
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full">{children}</main>
    </div>
  )
}
