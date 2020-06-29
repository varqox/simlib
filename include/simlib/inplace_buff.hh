#pragma once

#include "simlib/concat_common.hh"
#include "simlib/string_view.hh"

class InplaceBuffBase {
public:
	size_t size = 0;

protected:
	size_t max_size_;
	char* p_;
	char* p_value_when_unallocated_;

public:
	/**
	 * @brief Changes buffer's size and max_size if needed, but in the latter
	 *   case all the data are lost
	 *
	 * @param n new buffer's size
	 */
	void lossy_resize(size_t n) {
		if (n > max_size_) {
			max_size_ = std::max(max_size_ << 1, n);
			deallocate();
			try {
				p_ = new char[max_size_];
			} catch (...) {
				p_ = reinterpret_cast<char*>(&p_) + sizeof(p_);
				max_size_ = 0;
				throw;
			}
		}

		size = n;
	}

	/**
	 * @brief Changes buffer's size and max_size if needed, preserves data
	 *
	 * @param n new buffer's size
	 */
	constexpr void resize(size_t n) {
		if (n > max_size_) {
			size_t new_ms = std::max(max_size_ << 1, n);
			char* new_p = new char[new_ms];
			std::copy(p_, p_ + size, new_p);
			deallocate();

			p_ = new_p;
			max_size_ = new_ms;
		}

		size = n;
	}

	constexpr void clear() noexcept { size = 0; }

	constexpr char* begin() noexcept { return data(); }

	[[nodiscard]] constexpr const char* begin() const noexcept {
		return data();
	}

	constexpr char* end() noexcept { return data() + size; }

	[[nodiscard]] constexpr const char* end() const noexcept {
		return data() + size;
	}

	[[nodiscard]] constexpr const char* cbegin() const noexcept {
		return data();
	}

	[[nodiscard]] constexpr const char* cend() const noexcept {
		return data() + size;
	}

	constexpr char* data() noexcept { return p_; }

	[[nodiscard]] constexpr const char* data() const noexcept { return p_; }

	[[nodiscard]] constexpr size_t max_size() const noexcept {
		return max_size_;
	}

	constexpr char& front() noexcept { return (*this)[0]; }

	[[nodiscard]] constexpr char front() const noexcept { return (*this)[0]; }

	constexpr char& back() noexcept { return (*this)[size - 1]; }

	[[nodiscard]] constexpr char back() const noexcept {
		return (*this)[size - 1];
	}

	constexpr char& operator[](size_t i) noexcept { return p_[i]; }

	constexpr char operator[](size_t i) const noexcept { return p_[i]; }

	// NOLINTNEXTLINE(google-explicit-constructor)
	constexpr operator StringView() const& noexcept { return {data(), size}; }

	// Do not allow to create StringView from a temporary object
	constexpr operator StringView() const&& = delete;

	// Do not allow to create StringBase<char> from a temporary object
	// NOLINTNEXTLINE(google-explicit-constructor)
	operator StringBase<char>() & noexcept { return {data(), size}; }

	operator StringBase<char>() && = delete;

	[[nodiscard]] std::string to_string() const { return {data(), size}; }

	constexpr CStringView to_cstr() & {
		resize(size + 1);
		(*this)[--size] = '\0';
		return {data(), size};
	}

	// Do not allow to create CStringView of a temporary object
	constexpr CStringView to_cstr() && = delete;

protected:
	constexpr InplaceBuffBase(size_t s, size_t max_s, char* p,
	                          char* p_value_when_unallocated) noexcept
	: size(s)
	, max_size_(max_s)
	, p_(p)
	, p_value_when_unallocated_(p_value_when_unallocated) {}

	constexpr InplaceBuffBase(const InplaceBuffBase&) noexcept = default;
	constexpr InplaceBuffBase(InplaceBuffBase&&) noexcept = default;
	InplaceBuffBase& operator=(const InplaceBuffBase&) noexcept = default;
	InplaceBuffBase& operator=(InplaceBuffBase&&) noexcept = default;

	[[nodiscard]] bool is_allocated() const noexcept {
		return (p_ != p_value_when_unallocated_);
	}

	void deallocate() noexcept {
		if (is_allocated()) {
			delete[] p_;
		}
	}

public:
	virtual ~InplaceBuffBase() { deallocate(); }

	template <class... Args,
	          std::enable_if_t<(is_string_argument<Args> and ...), int> = 0>
	constexpr InplaceBuffBase& append(Args&&... args) {
		[this](auto&&... str) {
			size_t k = size;
			size_t final_len = (size + ... + string_length(str));
			resize(final_len);
			auto append_impl = [&](auto&& s) {
				auto sl = string_length(s);
				std::copy(::data(s), ::data(s) + sl, data() + k);
				k += sl;
			};
			(void)append_impl; // Fix GCC warning
			(append_impl(std::forward<decltype(str)>(str)), ...);
		}(stringify(std::forward<Args>(args))...);

		return *this;
	}
};

template <size_t N>
class InplaceBuff : public InplaceBuffBase {
private:
	std::array<char, N> a_;

	template <size_t M>
	friend class InplaceBuff;

	static_assert(N > 0, "Needed for accessing the array's 0-th element");

public:
	static constexpr size_t max_static_size = N;

	constexpr InplaceBuff() noexcept
	: InplaceBuffBase(0, N, nullptr, nullptr) {
		p_ = a_.data();
		p_value_when_unallocated_ = a_.data();
	}

	constexpr explicit InplaceBuff(size_t n)
	: InplaceBuffBase(n, std::max(N, n), nullptr, nullptr) {
		p_ = (n <= N ? a_.data() : new char[n]);
		p_value_when_unallocated_ = a_.data();
	}

	constexpr InplaceBuff(const InplaceBuff& ibuff)
	: InplaceBuff(ibuff.size) {
		std::copy(ibuff.data(), ibuff.data() + ibuff.size, data());
	}

	InplaceBuff(InplaceBuff&& ibuff) noexcept
	: InplaceBuffBase(ibuff.size, std::max(N, ibuff.max_size_), ibuff.p_,
	                  nullptr) {
		p_value_when_unallocated_ = a_.data();
		if (ibuff.is_allocated()) {
			p_ = ibuff.p_;
			ibuff.size = 0;
			ibuff.max_size_ = N;
			ibuff.p_ = ibuff.a_.data();

		} else {
			p_ = a_.data();
			std::copy(ibuff.data(), ibuff.data() + ibuff.size, p_);
			ibuff.size = 0;
		}
	}

	template <class T, std::enable_if_t<
	                      not std::is_integral_v<std::decay_t<T>> and
	                         not std::is_same_v<std::decay_t<T>, InplaceBuff>,
	                      int> = 0>
	// NOLINTNEXTLINE(bugprone-forwarding-reference-overload): see enable_if
	constexpr explicit InplaceBuff(T&& str)
	: InplaceBuff(string_length(str)) {
		std::copy(::data(str), ::data(str) + size, p_);
	}

	// Used to unify constructors, as constructor taking one argument is
	// explicit
	template <class... Args,
	          std::enable_if_t<(is_string_argument<Args> and ...), int> = 0>
	constexpr explicit InplaceBuff(std::in_place_t /*unused*/, Args&&... args)
	: InplaceBuff() {
		append(std::forward<Args>(args)...);
	}

	template <
	   class Arg1, class Arg2, class... Args,
	   std::enable_if_t<
	      not std::is_same_v<std::remove_cv_t<std::remove_reference_t<Arg1>>,
	                         std::in_place_t>,
	      int> = 0>
	constexpr InplaceBuff(Arg1&& arg1, Arg2&& arg2, Args&&... args)
	: InplaceBuff(std::in_place, std::forward<Arg1>(arg1),
	              std::forward<Arg2>(arg2), std::forward<Args>(args)...) {}

	template <size_t M, std::enable_if_t<M != N, int> = 0>
	constexpr explicit InplaceBuff(const InplaceBuff<M>& ibuff)
	: InplaceBuff(ibuff.size) {
		std::copy(ibuff.data(), ibuff.data() + ibuff.size, data());
	}

	template <size_t M, std::enable_if_t<M != N, int> = 0>
	explicit InplaceBuff(InplaceBuff<M>&& ibuff) noexcept
	: InplaceBuffBase(ibuff.size, N, ibuff.p_, nullptr) {
		p_value_when_unallocated_ = a_.data();
		if (ibuff.size <= N) {
			p_ = a_.data();
			// max_size_ = N;
			std::copy(ibuff.data(), ibuff.data() + ibuff.size, p_);
			// Deallocate ibuff memory
			if (ibuff.is_allocated()) {
				delete[] std::exchange(ibuff.p_, nullptr);
			}

		} else if (ibuff.is_allocated()) {
			p_ = ibuff.p_; // Steal the allocated string
			max_size_ = ibuff.max_size_;
		} else {
			// N < ibuff.size <= M
			p_ = new char[ibuff.size];
			max_size_ = ibuff.size;
			std::copy(ibuff.data(), ibuff.data() + ibuff.size, p_);
		}

		// Take care of the ibuff's state
		ibuff.size = 0;
		ibuff.max_size_ = M;
		ibuff.p_ = ibuff.a_.data();
	}

	~InplaceBuff() override { assert(p_value_when_unallocated_ == a_.data()); }

	constexpr InplaceBuff& operator=(const InplaceBuff& ibuff) {
		if (this == &ibuff) {
			return *this;
		}
		lossy_resize(ibuff.size);
		std::copy(ibuff.data(), ibuff.data() + ibuff.size, data());
		return *this;
	}

	constexpr InplaceBuff& operator=(InplaceBuff&& ibuff) noexcept {
		assign_move_impl(std::move(ibuff));
		return *this;
	}

	template <class T,
	          std::enable_if_t<not std::is_same_v<std::decay_t<T>, InplaceBuff>,
	                           int> = 0>
	// NOLINTNEXTLINE(misc-unconventional-assign-operator)
	constexpr InplaceBuff& operator=(T&& str) {
		auto len = string_length(str);
		lossy_resize(len);
		std::copy(::data(str), ::data(str) + len, data());
		return *this;
	}

	template <size_t M, std::enable_if_t<M != N, int> = 0>
	constexpr InplaceBuff& operator=(const InplaceBuff<M>& ibuff) {
		lossy_resize(ibuff.size);
		std::copy(ibuff.data(), ibuff.data() + ibuff.size, data());
		return *this;
	}

	template <size_t M, std::enable_if_t<M != N, int> = 0>
	constexpr InplaceBuff& operator=(InplaceBuff<M>&& ibuff) noexcept {
		assign_move_impl(std::move(ibuff));
		return *this;
	}

private:
	template <size_t M>
	InplaceBuff& assign_move_impl(InplaceBuff<M>&& ibuff) {
		if (ibuff.is_allocated() and ibuff.max_size() >= max_size()) {
			// Steal the allocated string
			if (is_allocated()) {
				delete[] p_;
			}

			p_ = ibuff.p_;
			size = ibuff.size;
			max_size_ = ibuff.max_size_;

		} else {
			*this = ibuff; // Copy data
			if (ibuff.is_allocated()) {
				delete[] ibuff.p_;
			}
		}

		// Take care of the ibuff's state
		ibuff.p_ = ibuff.a_.data();
		ibuff.size = 0;
		ibuff.max_size_ = M;

		return *this;
	}
};

template <size_t N>
std::string& operator+=(std::string& str, const InplaceBuff<N>& ibs) {
	return str.append(ibs.data(), ibs.size);
}

// This function allows @p str to be converted to StringView, but
// keep in mind that if any StringView or alike value generated from the result
// of this function cannot be saved to a variable! -- it would (and probably
// will) cause use-after-free error, because @p str will be already deleted when
// the initialization is done
template <size_t N>
constexpr StringView
intentional_unsafe_string_view(const InplaceBuff<N>&& str) noexcept {
	return StringView(static_cast<const InplaceBuff<N>&>(str));
}

// This function allows @p str to be converted to CStringView, but
// keep in mind that if any StringView or alike value generated from the result
// of this function cannot be saved to a variable! -- it would (and probably
// will) cause use-after-free error, because @p str will be already deleted when
// the initialization is done
template <size_t N>
constexpr CStringView
intentional_unsafe_cstring_view(InplaceBuff<N>&& str) noexcept {
	return static_cast<InplaceBuff<N>&>(str).to_cstr();
}

template <size_t T>
constexpr auto string_length(const InplaceBuff<T>& buff)
   -> decltype(buff.size) {
	return buff.size;
}

template <size_t N, class... Args,
          std::enable_if_t<(is_string_argument<Args> and ...), int> = 0>
InplaceBuff<N>& back_insert(InplaceBuff<N>& buff, Args&&... args) {
	buff.append(std::forward<Args>(args)...);
	return buff;
}
