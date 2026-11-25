import { createApp } from 'vue'
import App from './App.vue'
import './style.css'

// `vee ui` prints its address with this process's access token in the URL
// fragment, which the browser never sends to the server. Keep it for this tab
// and take it out of the address bar and history.
const supplied = /(?:^|&)token=([0-9a-f]{64})(?:&|$)/.exec(window.location.hash.slice(1))
if (supplied) {
  try { window.sessionStorage.setItem('vee.network-ui.token.v1', supplied[1]) } catch {}
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
}

createApp(App).mount('#app')
