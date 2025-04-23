const storageHelper = (storage = sessionStorage) => ({
    set: (key, value) => {
        try {
            storage.setItem(key, JSON.stringify(value));
        } catch (e) {
            console.warn(`Unable to set item "${key}" in storage:`, e);
        }
    },

    get: (key) => {
        try {
            const value = storage.getItem(key);
            return value ? JSON.parse(value) : null;
        } catch (e) {
            console.warn(`Unable to get item "${key}" from storage:`, e);
            return null;
        }
    },

    remove: (key) => {
        try {
            storage.removeItem(key);
        } catch (e) {
            console.warn(`Unable to remove item "${key}" from storage:`, e);
        }
    },

    clear: () => {
        try {
            storage.clear();
        } catch (e) {
            console.warn("Unable to clear storage:", e);
        }
    }
});

export const sessionStore = storageHelper(sessionStorage);
export const localStore = storageHelper(localStorage);
