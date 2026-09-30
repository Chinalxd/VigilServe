import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import './Layout.css'

export default function Layout({ servers, loading, onConnect }) {
  return (
    <div style={{ display: 'flex', height: '100vh', width: '100%' }}>
      <Sidebar servers={servers} loading={loading} onConnect={onConnect} />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
