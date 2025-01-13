import { Request, Response, Router } from "express";
import { authMiddleware } from "../../middleware";
import PaymentModel from "../../model/PaymentModel";

// Create a new instance of the Express Router
const PaymentRouter = Router();

// @route    Get api/payments/:userId
// @desc     Get all payments for user
// @access   Private
PaymentRouter.get(
    '/:userId',
    authMiddleware,
    async (req: Request, res: Response) => {
        const userId = req.params.userId;
        try {
            const payments = await PaymentModel.find({ userId: userId });
            res.json({ payments: payments });
        } catch (err) {
            console.log('error finding payments ===> ', err);
            res.status(500).send({ err });
        }
    }
)

export default PaymentRouter;