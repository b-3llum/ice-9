import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import CampaignList from './components/CampaignList'
import CampaignDetail from './components/CampaignDetail'
import ToolsList from './components/ToolsList'
import AIPanel from './components/AIPanel'
import IntelView from './components/IntelView'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<CampaignList />} />
        <Route path="/campaigns/:id" element={<CampaignDetail />} />
        <Route path="/campaigns/:id/intel" element={<IntelView />} />
        <Route path="/tools" element={<ToolsList />} />
        <Route path="/ai" element={<AIPanel />} />
      </Routes>
    </Layout>
  )
}
