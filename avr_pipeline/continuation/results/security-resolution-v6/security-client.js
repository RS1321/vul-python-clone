(() => {
      const original = window.fetch;
      window.fetch = function(input, init) {
        const request = new Request(input, init);
        if (new URL(request.url).origin === location.origin && !['GET','HEAD','OPTIONS'].includes(request.method)) {
          const token = document.querySelector('meta[name=csrf-token]');
          if (token) { const headers = new Headers(request.headers); headers.set('X-CSRFToken', token.content); return original(new Request(request, {headers})); }
        }
        return original(request);
      };
    })();