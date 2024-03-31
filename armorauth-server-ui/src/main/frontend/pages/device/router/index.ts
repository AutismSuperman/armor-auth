import { createRouter, createWebHistory } from 'vue-router';
import DeviceActivate from '@/pages/device/views/DeviceActivate.vue';
import DeviceActivated from '@/pages/device/views/DeviceActivated.vue';
import { useMetaTitle } from '@/composables/meta-title';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/activate',
      name: 'deviceActivate',
      meta: {
        title: '设备激活',
      },
      component: DeviceActivate,
    },
    {
      path: '/activated',
      name: 'deviceActivated',
      meta: {
        title: '激活成功',
      },
      component: DeviceActivated,
    },
  ],
});

router.afterEach((to) => {
  useMetaTitle(to);
});

export default router;
