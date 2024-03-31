import { createRouter, createWebHistory } from 'vue-router';
import Login from '@/pages/login/views/Login.vue';
import { useMetaTitle } from '@/composables/meta-title';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      meta: {
        title: '用户登录',
      },
      component: Login,
    },
  ],
});

router.afterEach((to) => {
  useMetaTitle(to);
});

export default router;
