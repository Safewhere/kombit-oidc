<template>
  <div class="container">
    <header>
      <h1>SPA OIDC client application</h1>
      <div>
        <div>
          <div class="security-level">
            <label for="auth-level">Select Security Level</label>
            <select id="auth-level" v-model="selectedSecurityLevel">
              <option value="" selected>None</option>
              <option
                v-for="option in securityLevels"
                :key="option"
                :value="option"
              >
                {{ option }}
              </option>
            </select>
          </div>
          <div class="security-level max-age">
            <label for="auth-level">max_age</label>
            <input type="number" id="max-age" v-model="maxAge" />
          </div>
          <div class="security-level">
            <label for="auth-method">Authn Request Method</label>
            <select id="auth-method" v-model="selectedAuthnMethod">
              <option value="GET" selected>GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
          <div v-if="!error">
            <div v-if="!user">
              <button @click="login(false, false)">Sign in</button>
            </div>
            <template v-if="user">
              <h4>Welcome, {{ user.profile.name }}</h4>
              <button @click="login(false, false)">Re-Authenticate</button>
              <button @click="login(true, false)">Force Authentication</button>
              <button @click="login(false, true)">
                Passive Authentication
              </button>
              <button @click="logout">Sign out</button>
            </template>
          </div>
          <div v-if="error">
            <div>
              <button @click="login(false, false)">Sign in</button>
            </div>
          </div>
        </div>
      </div>
    </header>
    <div v-if="!error">
      <div v-if="user">
        <div v-if="idToken">
          <h2>ID Token</h2>
          <p class="token">{{ idToken }}</p>
          <div class="decoded" v-if="idTokenHeader">
            <h3>Header</h3>
            <p class="token">{{ idTokenHeader }}</p>
          </div>
          <div class="decoded" v-if="idTokenPayload">
            <h3>Payload</h3>
            <p class="token">{{ idTokenPayload }}</p>
          </div>
        </div>

        <div v-if="accessToken">
          <h2>Access Token</h2>
          <p class="token">{{ accessToken }}</p>
          <div class="decoded" v-if="accessTokenHeader">
            <h3>Header</h3>
            <p>{{ accessTokenHeader }}</p>
          </div>
          <div class="decoded" v-if="accessTokenPayload">
            <h3>Payload</h3>
            <p>{{ accessTokenPayload }}</p>
          </div>
        </div>

        <div v-if="refreshToken">
          <h2>Refresh Token</h2>
          <p class="token">{{ refreshToken }}</p>
          <div class="decoded" v-if="refreshTokenHeader">
            <h3>Header</h3>
            <p>{{ refreshTokenHeader }}</p>
          </div>
          <div class="decoded" v-if="refreshTokenPayload">
            <h3>Payload</h3>
            <p>{{ refreshTokenPayload }}</p>
          </div>
        </div>
      </div>
    </div>
    <ErrorView v-if="error" :error="error" :description="description" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from "vue";
import { useRoute } from "vue-router";
import { authService } from "./../authService";
import { isAuthReady } from "./../useAuthState";

import ErrorView from "./ErrorView.vue";
import { AUTH_FORM_SETTINGS } from '../constants'; 
import { sessionStore } from '../storageHelper';

// Auth state
const user = ref(null);
const accessToken = ref(null);
const idToken = ref(null);
const refreshToken = ref(null);
const accessTokenHeader = ref(null);
const accessTokenPayload = ref(null);
const idTokenHeader = ref(null);
const idTokenPayload = ref(null);
const refreshTokenHeader = ref(null);
const refreshTokenPayload = ref(null);

// Form settings
const selectedSecurityLevel = ref("");
const selectedAuthnMethod = ref("GET");
const maxAge = ref(null);

// Error handling
const route = useRoute();
const error = computed(() => route.query.error || "");
const description = computed(() => route.query.description || "");

const securityLevels = [
  "https://data.gov.dk/concept/core/nsis/loa/High",
  "https://data.gov.dk/concept/core/nsis/loa/Low",
  "https://data.gov.dk/concept/core/nsis/loa/Substantial",
  "urn:dk:gov:saml:attribute:AssuranceLevel:1",
  "urn:dk:gov:saml:attribute:AssuranceLevel:2",
  "urn:dk:gov:saml:attribute:AssuranceLevel:3",
  "urn:dk:gov:saml:attribute:AssuranceLevel:4",
];

const login = async (isForceAuthn, isPassive) => {
  try {
    await authService.login(
      selectedSecurityLevel.value,
      maxAge.value,
      isForceAuthn,
      isPassive,
      selectedAuthnMethod.value == "POST"
    );
    
    user.value = await authService.getUser();
    accessToken.value = await authService.getAccessToken();
    idToken.value = await authService.getIdToken();
    refreshToken.value = await authService.getRefreshToken();

    var decodedAccessToken = await authService.decodeToken(accessToken.value);
    if (decodedAccessToken) {
      accessTokenHeader.value = decodedAccessToken.header;
      accessTokenPayload.value = decodedAccessToken.payload;
    }

    var decodedIdToken = await authService.decodeToken(idToken.value);
    if (decodedIdToken) {
      idTokenHeader.value = decodedIdToken.header;
      idTokenPayload.value = decodedIdToken.payload;
    }

    if (refreshToken.value) {
      var decodedRefreshToken = await authService.decodeToken(refreshToken.value);
      if (decodedRefreshToken) {
        refreshTokenHeader.value = decodedRefreshToken.header;
        refreshTokenPayload.value = decodedRefreshToken.payload;
      }
    }
  } catch (error) {
    console.error("Login failed:", error);
    alert("Login failed. Please check the console for more details.");
  }
};

const logout = async () => {
  try {
    await authService.logout();
    user.value = null;
    accessToken.value = null;
    idToken.value = null;
    refreshToken.value = null;
    selectedSecurityLevel.value = "";
  } catch (error) {
    console.error("Logout failed:", error);
  }
};

const loadUserTokens = async () => {
  user.value = await authService.getUser();
  if (!user.value) return;

  accessToken.value = await authService.getAccessToken();
  idToken.value = await authService.getIdToken();
  refreshToken.value = await authService.getRefreshToken();

  const decodedAccessToken = await authService.decodeToken(accessToken.value);
  if (decodedAccessToken) {
    accessTokenHeader.value = decodedAccessToken.header;
    accessTokenPayload.value = decodedAccessToken.payload;
  }

  const decodedIdToken = await authService.decodeToken(idToken.value);
  if (decodedIdToken) {
    idTokenHeader.value = decodedIdToken.header;
    idTokenPayload.value = decodedIdToken.payload;
  }

  if (refreshToken.value) {
    const decodedRefreshToken = await authService.decodeToken(refreshToken.value);
    if (decodedRefreshToken) {
      refreshTokenHeader.value = decodedRefreshToken.header;
      refreshTokenPayload.value = decodedRefreshToken.payload;
    }
  }

  isAuthReady.value = false;
};

onMounted(async () => {
  const savedSettings = sessionStore.get(AUTH_FORM_SETTINGS);
  if (savedSettings) {
    selectedSecurityLevel.value = savedSettings.selectedSecurityLevel || "";
    selectedAuthnMethod.value = savedSettings.isAuthnMethodPost ? "POST" : "GET";
    maxAge.value = savedSettings.maxAge;
  }

  await loadUserTokens();
});

watch(isAuthReady, async (newVal) => {
  if (!newVal) return;
  await loadUserTokens();
});
</script>

<style scoped>
body {
  background: #fff;
}

header {
  text-align: center;
  font-size: 24px;
}

header h1 {
  margin: 0;
  font-size: 2rem;
}

select,
input {
  padding: 10px;
  border-radius: 4px;
  border: 1px solid #ccc;
  width: 400px;
}

button {
  background-color: #4aaf51;
  color: white;
  border: none;
  padding: 10px 20px;
  font-size: 1rem;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.3s;
  margin-top: 20px;
}

button:not(:last-child) {
  margin-right: 20px;
}

button:hover {
  background-color: #4aaf51;
}

button:focus {
  outline: none;
}

p {
  font-size: 14px;
  color: #333;
}

.token {
  background-color: #dff0d8;
  border-radius: 4px;
  padding: 15px;
  margin-top: 20px;
  word-break: break-word;
  max-width: 100%;
  white-space: pre-wrap;
}

h2 {
  color: #17a2b8;
  margin-top: 30px;
  font-weight: 600;
}

.decoded {
  margin-top: 20px;
  background-color: #dff0d8;
  border-radius: 4px;
  padding: 15px;
  margin-top: 20px;
  word-break: break-word;
  max-width: 100%;
  white-space: pre-wrap;
}

.decoded h3 {
  color: #17a2b8;
  font-weight: 600;
}

.decoded p {
  background-color: #fff;
  border-radius: 4px;
  padding: 15px;
  margin-top: 15px;
  word-break: break-word;
  max-width: 100%;
  white-space: pre-wrap;
}

.security-level {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 20px;
  font-size: 1rem;
  margin: 20px 0;
}

.security-level label {
  width: 170px;
  text-align: left;
}
</style>
