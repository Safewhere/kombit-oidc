<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { authService } from './../authService';  // Ensure this imports your authService

const user = ref<any>(null);
const accessToken = ref<string | null>(null);
const idToken = ref<string | null>(null);
const accessTokenHeader = ref<any>(null);
const accessTokenPayload = ref<any>(null);
const idTokenHeader = ref<any>(null);
const idTokenPayload = ref<any>(null);
const selectedSecurityLevel = ref<string>('');


const securityLevels = [
  "https://data.gov.dk/concept/core/nsis/loa/High",
  "https://data.gov.dk/concept/core/nsis/loa/Low",
  "https://data.gov.dk/concept/core/nsis/loa/Substantial",
  "urn:dk:gov:saml:attribute:AssuranceLevel:1",
  "urn:dk:gov:saml:attribute:AssuranceLevel:2",
  "urn:dk:gov:saml:attribute:AssuranceLevel:3",
  "urn:dk:gov:saml:attribute:AssuranceLevel:4"
];

const login = async () => {
  try {
    await authService.login();
    user.value = await authService.getUser();
    accessToken.value = await authService.getAccessToken();
    idToken.value = await authService.getIdToken();

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
  } catch (error) {
    console.error("Login failed:", error);
  }
};

const logout = async () => {
  try {
    await authService.logout();
    user.value = null;
    accessToken.value = null;
    idToken.value = null;
    selectedSecurityLevel.value = '';
  } catch (error) {
    console.error("Logout failed:", error);
  }
};

const forceAuthn = async () => {
  try {
    await authService.forceAuthn(selectedSecurityLevel.value);
  } catch (error) {
    console.error("forceAuthn failed:", error);
  }
};

onMounted(async () => {
  user.value = await authService.getUser(); 
  if (!user.value) {
    return; 
  }
  accessToken.value = await authService.getAccessToken(); 
  idToken.value = await authService.getIdToken();  

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
});
</script>

<template>
  <div>
    <header>
      <h1>SPA OIDC client application</h1>
      <div>
        <div v-if="!user">
          <button @click="login">Login</button>
        </div>
        <div v-else>
          <div class="security-level">
            <label for="auth-level">Select Security Level:</label>
            <select id="auth-level" v-model="selectedSecurityLevel">
              <option value="" selected>None</option>
              <option v-for="option in securityLevels" :key="option" :value="option">
                {{ option }}
              </option>
            </select>
          </div>

          <h4>Welcome, {{ user.profile.name }}</h4>
          <button @click="logout">Logout</button>
          <button @click="forceAuthn">Force authn</button>
        </div>
      </div>
    </header>
    <div v-if="user">
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
    </div>

    
  </div>
</template>

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

select {
  padding: 10px;
  border-radius: 4px;
  border: 1px solid #ccc;
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
</style>
