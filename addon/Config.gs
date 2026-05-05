var APP_NAME = 'MailWatch Tower';
var BACKEND_BASE_URL = 'https://goto-highest-assess-llc.trycloudflare.com';
var API_TIMEOUT_MS = 15000;
var MAX_BODY_CHARS = 20000;
var MAX_ATTACHMENTS = 30;

var CATEGORY_COLORS = {
  sender: '#A67C52',
  links: '#0B3D91',
  attachments: '#E91E63',
  content: '#000000',
  headers: '#6A1B9A',
  metadata: '#4A4A4A',
};

var CATEGORY_LABELS = {
  sender: 'Sender identity',
  links: 'Links and URLs',
  attachments: 'Attachments',
  content: 'Content and social engineering',
  headers: 'Headers and authentication',
  metadata: 'Metadata and context',
};

var VERDICT_COLORS = {
  Safe: '#188038',
  'Low Risk': '#4FC3F7',
  Suspicious: '#FBC02D',
  'High Risk': '#F57C00',
  Dangerous: '#D93025',
};

// Category color explains the type of risk signal.
// Verdict color explains overall risk severity.
