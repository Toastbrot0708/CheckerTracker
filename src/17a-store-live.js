/* ============================================================================
   MODULE: store overrides for live operation
   ---------------------------------------------------------------------------
   The store still carries a seedDemo() from when a simulated estate shipped
   with the app. That estate is gone, so the function is replaced here with
   one that says so rather than quietly producing an empty assessment that
   would look like a failed scan.
   ========================================================================= */
(function () {
  'use strict';

  CT.store.seedDemo = function () {
    if (CT.ui && CT.ui.shell && CT.ui.shell.toast) {
      CT.ui.shell.toast('No demo data ships with this build — run a real assessment instead', 'warn', 4500);
    }
    return null;
  };
})();
