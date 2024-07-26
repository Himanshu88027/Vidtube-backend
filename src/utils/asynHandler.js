const asyncHandler = (requstFunction) => {
    return (req, res, next) => {
        Promise
            .resolve((requstFunction(req, res, next)))
            .catch((error) => next(error))
    }
}

export { asyncHandler }