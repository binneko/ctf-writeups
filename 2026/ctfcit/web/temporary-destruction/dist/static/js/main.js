(() => {
    const el = document.getElementById('inp');
    if (!el) return;

    el.addEventListener('keydown', e => {
        if (e.key === 'Tab') {
            e.preventDefault();
            const s = el.selectionStart, en = el.selectionEnd;
            el.value = el.value.slice(0, s) + '  ' + el.value.slice(en);
            el.selectionStart = el.selectionEnd = s + 2;
        }
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            el.closest('form').submit();
        }
    });

    const res = document.querySelector('.response');
    if (res) res.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
})();
