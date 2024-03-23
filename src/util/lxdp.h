/** netmill: Linux XDP interface
2024, Simon Zolin */

/*
lxdp_attach lxdp_close
lxdp_maps_link
lxdp_error
Socket:
	lxdpsk_create lxdpsk_close
	lxdpsk_fd
	lxdpsk_enable
	lxdpsk_read
	lxdpsk_write
	lxdpsk_flush
	lxdpsk_buf_alloc lxdpsk_buf_release
*/

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include <poll.h>

typedef struct lxdp lxdp;
struct lxdp {
	uint if_index;
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;

	const char *err_func;
	int err_code;
	char error[100];
};

typedef struct lxdpbuf lxdpbuf;
struct lxdpbuf {
	uint off;
	uint off_ip;
	uint len;
	u_char *data;
};

#define lxdpbuf_data(b)  (void*)((b)->data + (b)->off)
#define lxdpbuf_data_off(b, offset)  (void*)((b)->data + offset)

#define lxdpbuf_shift(b, by)  (b)->off += by

struct _lxdp_offset {
	uint64 off;
	void *ptr;
};

typedef struct lxdpsk lxdpsk;
struct lxdpsk {
	struct lxdp *x;

	void *area; // memory region for the packet data
	struct xsk_umem *umem;

	struct lxdpbuf *ubufs;
	struct _lxdp_offset *offsets;
	uint n_free;
	uint n_total;

	struct xsk_ring_prod fq; // fill-queue: we set the frame offsets where the kernel will write RX packets
	struct xsk_ring_cons rx; // kernel writes RX packet pointers here
	uint64 rx_packets;
	uint64 rx_bytes;

	struct xsk_ring_prod tx; // we write TX packet pointers here
	struct xsk_ring_cons cq; // completion-queue: kernel writes the frame offsets to the completed TX packets here
	uint64 tx_packets;
	uint64 tx_bytes;

	struct xsk_socket *xsk;
	int xsk_fd;
};

#define _LXDP_ERR(x, f, e) \
do { \
	x->err_func = f; \
	x->err_code = e; \
} while (0)

/** Get last error message */
static inline const char* lxdp_error(struct lxdp *x)
{
	ffsz_format(x->error, sizeof(x->error), "%s(): %u", x->err_func, x->err_code);
	return x->error;
}

static inline int lxdp_close(struct lxdp *x)
{
	if (x->if_index) {
		bpf_xdp_detach(x->if_index, 0, NULL);
		x->if_index = 0;
	}

	bpf_object__close(x->bpf_obj);
	x->bpf_prog = NULL;
	x->bpf_obj = NULL;
	return 0;
}

struct lxdp_attach_conf {
	int dummy;
};

/** Load BPF program and attach to interface. */
static inline int lxdp_attach(struct lxdp *x, const char *obj_filename, uint if_index, struct lxdp_attach_conf *conf)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
		_LXDP_ERR(x, "setrlimit", errno);
		return -1;
	}

	int e;
	if (!(x->bpf_obj = bpf_object__open_file(obj_filename, NULL))) {
		_LXDP_ERR(x, "bpf_object__open_file", errno);
		goto err;
	}

	if (!(x->bpf_prog = bpf_object__next_program(x->bpf_obj, NULL))) {
		_LXDP_ERR(x, "bpf_object__next_program", errno);
		goto err;
	}
	bpf_program__set_type(x->bpf_prog, BPF_PROG_TYPE_XDP);

	if ((e = bpf_object__load(x->bpf_obj))) {
		_LXDP_ERR(x, "bpf_object__load", -e);
		goto err;
	}

	uint f = XDP_FLAGS_UPDATE_IF_NOEXIST;
	if ((e = bpf_xdp_attach(if_index, bpf_program__fd(x->bpf_prog), f, NULL))) {
		_LXDP_ERR(x, "bpf_xdp_attach", -e);
		goto err;
	}
	x->if_index = if_index;
	return 0;

err:
	lxdp_close(x);
	return -1;
}

struct lxdp_map_name {
	char name[24];
	uint map_off; // offset to struct bpf_map*
};

/** Fill BPF map pointers. */
static inline int lxdp_maps_link(struct lxdp *x, const struct lxdp_map_name *maps, void *base)
{
	struct bpf_map *m;
	bpf_object__for_each_map(m, x->bpf_obj) {
		for (uint i = 0;  ;  i++) {
			if (!maps[i].name[0]) {
				_LXDP_ERR(x, "", ENOENT);
				return -1;
			}
			if (ffsz_eq(((void**)m)[1], maps[i].name)) {
				*(void**)((char*)base + maps[i].map_off) = m;
				break;
			}
		}
	}
	return 0;
}

/** Close XDP socket. */
static inline void lxdpsk_close(struct lxdpsk *sk)
{
	xsk_socket__delete(sk->xsk);
	sk->xsk = NULL;
	xsk_umem__delete(sk->umem);
	sk->umem = NULL;
	free(sk->offsets);
	sk->offsets = NULL;
	free(sk->ubufs);
	sk->ubufs = NULL;
}

static uint _lxdp_fq_reserve(struct lxdpsk *sk)
{
	uint n = xsk_prod_nb_free(&sk->fq, sk->n_free);

	uint fq_idx;
	if (!xsk_ring_prod__reserve(&sk->fq, n, &fq_idx)) {
		FF_ASSERT(0);
		return 0;
	}

	for (uint i = 0;  i < n;  i++) {
		FF_ASSERT(sk->n_free > 0);
		sk->n_free--;
		*xsk_ring_prod__fill_addr(&sk->fq, fq_idx++) = sk->offsets[sk->n_free].off;
#ifdef FF_DEBUG
		sk->offsets[sk->n_free].off = ~0ULL;
		sk->offsets[sk->n_free].ptr = NULL;
#endif
	}

	xsk_ring_prod__submit(&sk->fq, n);
	return n;
}

static inline uint _lxdp_cq_reclaim(struct lxdpsk *sk)
{
	uint n = xsk_cons_nb_avail(&sk->cq, 256);
	if (n < 256)
		return 0;

	uint cq_idx;
	n = xsk_ring_cons__peek(&sk->cq, 256, &cq_idx);
	if (!n)
		return 0;

	for (uint i = 0;  i < n;  i++) {
		FF_ASSERT(sk->n_free < sk->n_total);
		sk->offsets[sk->n_free].off = *xsk_ring_cons__comp_addr(&sk->cq, cq_idx++);
		uint ibuf = sk->offsets[sk->n_free].off / XSK_UMEM__DEFAULT_FRAME_SIZE;
		sk->offsets[sk->n_free].ptr = &sk->ubufs[ibuf];
		sk->n_free++;
	}
	xsk_ring_cons__release(&sk->cq, n);
	return n;
}

struct lxdpsk_conf {
	uint rx_frames, tx_frames;
	uint zero_copy :1;
};

/** Create XDP socket and buffers. */
static inline int lxdpsk_create(struct lxdp *x, struct lxdpsk *sk, const char *if_name
	, uint if_queue, struct lxdpsk_conf *conf)
{
	if (!conf->rx_frames)
		conf->rx_frames = 2048;
	if (!conf->tx_frames)
		conf->tx_frames = 2048;
	uint n_frames = conf->rx_frames + conf->tx_frames;

	int r;
	size_t cap = n_frames * XSK_UMEM__DEFAULT_FRAME_SIZE;
	if ((r = posix_memalign(&sk->area, getpagesize(), cap))) {
		_LXDP_ERR(x, "posix_memalign", r);
		return -1;
	}
	if (!(sk->ubufs = malloc(n_frames * sizeof(struct lxdpbuf))))
		return -1;

	struct xsk_umem_config xuc = {
		.fill_size = conf->rx_frames,
		.comp_size = conf->tx_frames,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	};
	if ((r = xsk_umem__create(&sk->umem, sk->area, cap, &sk->fq, &sk->cq, &xuc))) {
		_LXDP_ERR(x, "xsk_umem__create", -r);
		return -1;
	}

	struct xsk_socket_config xsc = {
		.rx_size = conf->rx_frames,
		.tx_size = conf->tx_frames,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	};
	xsc.bind_flags |= (conf->zero_copy) ? XDP_ZEROCOPY : 0;
	if ((r = xsk_socket__create(&sk->xsk, if_name, if_queue, sk->umem, &sk->rx, &sk->tx, &xsc))) {
		_LXDP_ERR(x, "xsk_socket__create", -r);
		return -1;
	}

	if (!(sk->offsets = malloc(n_frames * sizeof(struct _lxdp_offset))))
		return -1;
	for (uint i = 0;  i < n_frames;  i++) {
		sk->offsets[i].off = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
		sk->offsets[i].ptr = &sk->ubufs[i];
	}
	sk->n_free = n_frames;
	sk->n_total = n_frames;

	_lxdp_fq_reserve(sk);

	sk->xsk_fd = xsk_socket__fd(sk->xsk);
	sk->x = x;
	return 0;
}

#define lxdpsk_fd(sk)  (sk)->xsk_fd

/** Add XSK to BPF_MAP_TYPE_XSKMAP map. */
static inline int lxdpsk_enable(struct lxdpsk *sk, struct bpf_map *m)
{
	int r, fd;
	if ((fd = bpf_map__fd(m)) < 0) {
		_LXDP_ERR(sk->x, "bpf_map__fd", 0);
		return -1;
	}
	if ((r = xsk_socket__update_xskmap(sk->xsk, fd))) {
		_LXDP_ERR(sk->x, "xsk_socket__update_xskmap", -r);
		return -1;
	}
	return 0;
}

static inline int lxdpsk_read(struct lxdpsk *sk, struct lxdpbuf **v, uint n)
{
	uint rx_idx;
	if (!(n = xsk_ring_cons__peek(&sk->rx, n, &rx_idx)))
		return 0;

	uint total = 0;
	for (uint i = 0;  i < n;  i++) {
		const struct xdp_desc *xd = xsk_ring_cons__rx_desc(&sk->rx, rx_idx++);
		uint ibuf = xd->addr / XSK_UMEM__DEFAULT_FRAME_SIZE;
		struct lxdpbuf *buf = &sk->ubufs[ibuf];
		ffmem_zero_obj(buf);
		buf->len = xd->len;
		total += xd->len;
		buf->data = (u_char*)sk->area + xd->addr;
		v[i] = buf;
	}

	xsk_ring_cons__release(&sk->rx, n);

	sk->rx_bytes += total;
	sk->rx_packets += n;

	_lxdp_fq_reserve(sk);

	if (xsk_ring_prod__needs_wakeup(&sk->fq)) {
		// the kernel suspended the RX processing - now we must send a signal
		struct pollfd pl = {
			.fd = sk->xsk_fd,
			.events = POLLIN | POLLOUT,
		};
		int r = poll(&pl, 1, 0);
		if (ff_unlikely(r < 0)) {
			_LXDP_ERR(sk->x, "poll", errno);
		}
	}
	return n;
}

static inline uint lxdpsk_buf_alloc(struct lxdpsk *sk, struct lxdpbuf **v, uint n)
{
	n = ffmin(n, sk->n_free);
	for (uint i = 0;  i < n;  i++) {
		FF_ASSERT(sk->n_free > 0);
		sk->n_free--;
		struct lxdpbuf *b = sk->offsets[sk->n_free].ptr;
		ffmem_zero_obj(b);
		b->data = sk->area + sk->offsets[sk->n_free].off;
#ifdef FF_DEBUG
		sk->offsets[sk->n_free].off = ~0ULL;
		sk->offsets[sk->n_free].ptr = NULL;
#endif

		v[i] = b;
	}
	return n;
}

static inline void lxdpsk_buf_release(struct lxdpsk *sk, struct lxdpbuf *buf)
{
	FF_ASSERT(sk->n_free < sk->n_total);
	sk->offsets[sk->n_free].off = buf->data - (u_char*)sk->area;
	sk->offsets[sk->n_free].ptr = buf;
	sk->n_free++;
}

static inline uint lxdpsk_write(struct lxdpsk *sk, struct lxdpbuf **v, uint n)
{
	uint tx_idx;
	n = xsk_ring_prod__reserve(&sk->tx, n, &tx_idx);
	if (!n) {
		_lxdp_cq_reclaim(sk);
		n = xsk_ring_prod__reserve(&sk->tx, n, &tx_idx);
		if (!n) {
			FF_ASSERT(0);
			return 0;
		}
	}

	uint total = 0;
	for (uint i = 0;  i < n;  i++) {
		struct xdp_desc *xd = xsk_ring_prod__tx_desc(&sk->tx, tx_idx++);
		xd->addr = v[i]->data - (u_char*)sk->area;
		xd->len = v[i]->len;
		total += v[i]->len;
	}
	xsk_ring_prod__submit(&sk->tx, n);

	sk->tx_bytes += total;
	sk->tx_packets += n;
	return n;
}

static inline int lxdpsk_flush(struct lxdpsk *sk)
{
	if (!xsk_ring_prod__needs_wakeup(&sk->tx))
		return 0; // no need to signal the kernel

	return sendto(sk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}
