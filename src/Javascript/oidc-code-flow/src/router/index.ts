import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router';
import HomeView from '../views/HomeView.vue';
import { authService } from './../authService';
import { h } from 'vue';
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'home',
    component: HomeView,
  },
  {
    path: '/about',
    name: 'about',
    component: () => import('../views/AboutView.vue'),
  },
  {
    path: '/oidc_callback',
    name: 'oidc_callback',
    component: {
      render: () => h("div"),
    },
    beforeEnter: async (to, from, next) => {
      try {
        await authService.handleCallback();
        next('/');
      } catch (error) {
        console.error("OIDC callback error:", error);
        next('/');
      }
    },
  },
];

const router = createRouter({
  history: createWebHistory(), 
  routes,
});

export default router;
