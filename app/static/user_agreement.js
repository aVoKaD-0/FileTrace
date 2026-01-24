(function () {
    const toc = document.getElementById('uaToc');
    const toggleAll = document.getElementById('uaToggleAll');

    if (!toc) return;

    const links = Array.from(toc.querySelectorAll('a.ua-toc-link'));
    const targets = links
        .map((a) => document.querySelector(a.getAttribute('href')))
        .filter(Boolean);

    function setActiveByScroll() {
        const y = window.scrollY || window.pageYOffset;
        const headerOffset = 110;

        let bestIndex = 0;
        for (let i = 0; i < targets.length; i++) {
            const t = targets[i];
            const top = t.getBoundingClientRect().top + y;
            if (top - headerOffset <= y) bestIndex = i;
        }

        links.forEach((l) => l.classList.remove('ua-active'));
        if (links[bestIndex]) links[bestIndex].classList.add('ua-active');
    }

    let raf = null;
    window.addEventListener('scroll', function () {
        if (raf) return;
        raf = window.requestAnimationFrame(function () {
            raf = null;
            setActiveByScroll();
        });
    });

    setActiveByScroll();

    if (toggleAll) {
        toggleAll.addEventListener('click', function () {
            const isHidden = toc.style.display === 'none';
            toc.style.display = isHidden ? '' : 'none';
            toggleAll.textContent = isHidden ? 'Свернуть' : 'Развернуть';
        });
    }

    links.forEach((a) => {
        a.addEventListener('click', function (e) {
            const href = a.getAttribute('href');
            if (!href || href[0] !== '#') return;

            const target = document.querySelector(href);
            if (!target) return;

            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            history.replaceState(null, '', href);
        });
    });
})();
