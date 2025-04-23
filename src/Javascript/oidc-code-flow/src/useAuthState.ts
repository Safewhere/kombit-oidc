import { ref } from 'vue';

export const isAuthReady = ref(false);

export function useAuthState() {
    return {
        isAuthReady
    };
}
