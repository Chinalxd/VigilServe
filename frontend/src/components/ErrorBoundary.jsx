import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('App error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', minHeight: '100vh', padding: 40,
          fontFamily: '"Microsoft YaHei", sans-serif'
        }}>
          <h2 style={{ color: '#dc3545', marginBottom: 12 }}>页面加载异常</h2>
          <p style={{ color: '#6c757d', marginBottom: 20 }}>
            {this.state.error?.message || '未知错误'}
          </p>
          <button
            onClick={() => { this.setState({ hasError: false }); window.location.href = '/' }}
            className="btn"
          >
            返回首页
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

if (typeof window !== 'undefined') {
  window.addEventListener('error', (e) => {
    console.error('Global JS error:', e.message, e.filename, e.lineno)
  })
  window.addEventListener('unhandledrejection', (e) => {
    console.error('Unhandled promise rejection:', e.reason)
  })
}
