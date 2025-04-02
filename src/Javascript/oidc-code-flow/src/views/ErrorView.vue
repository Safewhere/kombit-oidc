<template>
  <!-- Error Section at Bottom -->
  <div v-if="error" class="error-box">
    <div class="error-header">
      <svg class="error-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
        <path fill="currentColor" d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18.25a1.25 1.25 0 1 1 1.25-1.25A1.25 1.25 0 0 1 12 20.25zm1.25-5.75h-2.5V7h2.5z"/>
      </svg>
      <h2>Error</h2>
    </div>
    <p><b>Error:</b> {{ error }}</p>
    <p v-if="description"><b>Description:</b> {{ description }}</p>
  </div>
</template>

<script setup>
defineProps({
  error: String,
  description: String
});
</script>

<style scoped>
.error-box {
  margin-top: 40px;
  padding: 20px;
  background: #ffebee;
  color: #c62828;
  border-radius: 6px;
  text-align: left;
}

.error-header {
  display: flex;
  align-items: center;
  gap: 10px;
}

.error-icon {
  width: 30px;
  height: 30px;
  color: #d32f2f;
}

button {
  background-color: #4aaf51;
  color: white;
  border: none;
  padding: 10px 20px;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.3s;
  margin-top: 20px;
}

button:hover {
  background-color: #388e3c;
}
</style>
