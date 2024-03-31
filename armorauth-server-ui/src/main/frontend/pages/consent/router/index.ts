import { createRouter, createWebHistory } from 'vue-router';
import Consent from '@/pages/consent/views/Consent.vue';
import { useMetaTitle } from '@/composables/meta-title';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/consent',
      name: 'consent',
      meta: {
        title: '用户授权',
      },
      component: Consent,
    }
  ],
});

router.afterEach((to) => {
  useMetaTitle(to);
});

export default router;
