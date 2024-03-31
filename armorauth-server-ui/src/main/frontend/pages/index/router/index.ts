import { createRouter, createWebHistory } from 'vue-router';
import index from '@/pages/index/views/Index.vue';
import { useMetaTitle } from '@/composables/meta-title';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      meta: {
        title: '默认页面',
      },
      component: index,
    },
  ],
});

router.afterEach((to) => {
  useMetaTitle(to);
});

export default router;
